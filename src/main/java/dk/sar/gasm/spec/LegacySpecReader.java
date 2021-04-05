package dk.sar.gasm.spec;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

import com.google.common.base.Strings;

import dk.sar.gasm.Assembler;
import dk.sar.gasm.AssemblerException;
import dk.sar.gasm.FileParserException;
import dk.sar.gasm.data.InstructionFormat;
import dk.sar.gasm.data.Mnemonic;
import dk.sar.gasm.data.OperandFormat;
import dk.sar.gasm.data.SpecFile;
import lombok.Getter;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/** Read spec files in the original format from Eddie Graham's version. */
@Slf4j
@RequiredArgsConstructor
public class LegacySpecReader implements SpecReader {
	private static enum State {
		ARCHITECTURE, REGISTERS, MNEMONIC_DATA, INSTRUCTION_FORMAT, ASSEMBLY_OP_TREE, ENDIAN, MIN_ADDRESSABLE_UNIT
	}

	@NonNull
	private final String fileName;

	private State currentlyParsing = null;
	private boolean architectureDeclared, registersDeclared, mnemDataDeclared, insFormatDeclared,
			assemblyOpTreeDeclared, endianDeclared, minAdrUnitDeclared;
	private OperandFormat currentMnemFormat;
	private Mnemonic currentMnemonic;
	private boolean doneGlobalEncodings, abortMnem;
	private boolean emptyLine = true;
	private boolean firstAssemblyOpTreeEntry = true;
	private boolean foundArchitecture, foundMnemData, foundInsFormat, foundAssemblyOpTree, foundEndian, foundMinAdrUnit;
	private boolean atOperandFieldEncodings, atLocalFieldEncodings, atInsFormat;
	private boolean foundFormatHeader = true;
	private String rootOpTreeEntry = "";
	@Getter private List<String> errorReport = new ArrayList<>();
	private SpecFile specFile = new SpecFile();

	@Override
	public SpecFile getSpecFile() throws IOException, FileParserException {
		scanSpecFile(fileName);

		if (!errorReport.isEmpty()) {
			throw new FileParserException("Error in specification file, see \"spec_error_report.txt\".", errorReport);
		} else {
			errorReport.add("No errors found within specification file.");
		}

		Assembler.writeLinesToFile("spec_error_report.txt", errorReport);

		return specFile;
	}

	private void scanSpecFile(String fileName) throws FileNotFoundException, FileParserException {
		// Two scanners as file is parsed twice. MnemonicData is analysed last for error
		// checking
		var lineCounter = 0;

		try (var inputFile = new Scanner(new FileInputStream(fileName))) {
			while (inputFile.hasNextLine()) {
				var fullSpecLine = inputFile.nextLine();
				var specLine = fullSpecLine;
				lineCounter++;

				var commentSplit = specLine.split(";"); // Comments (;...) omitted
				specLine = commentSplit[0].replaceAll("\\s+$", ""); // Remove end whitespace

				try {
					scanLineFirstPass(specLine);
				} catch (AssemblerException e) {
					var error = getErrorMessage(lineCounter, fullSpecLine, e.getMessage());
					errorReport.add(error);
				}
			}

			if (!foundArchitecture || !foundInsFormat || !foundAssemblyOpTree || !foundEndian || !foundMinAdrUnit) {
				var missingSections = "";
				if (!foundArchitecture) {
					missingSections += "\"architecture\" ";
				}
				if (!foundInsFormat) {
					missingSections += "\"instructionFormat\" ";
				}
				if (!foundAssemblyOpTree) {
					missingSections += "\"assemblyOpTree\" ";
				}
				if (!foundEndian) {
					missingSections += "\"endian\" ";
				}
				if (!foundMinAdrUnit) {
					missingSections += "\"minAddressableUnit\" ";
				}
				missingSections = missingSections.trim();
				try {
					throw new AssemblerException("Section/s " + missingSections + " missing from specification file.");
				} catch (AssemblerException e) {
					var error = e.getMessage();
					errorReport.add(error);
				}
			}

			if (!errorReport.isEmpty()) {
				throw new FileParserException("Error in specification file, see \"spec_error_report.text\".",
						errorReport);
			}
		} catch (FileNotFoundException e) {
			log.error("Specification file \"{}\" not found.", fileName);
			throw e;
		}

		lineCounter = 0;
		String fullSpecLine = null;
		resetDeclarationBooleans();

		try (var inputFile2 = new Scanner(new FileInputStream(fileName))) {
			while (inputFile2.hasNextLine()) {
				fullSpecLine = inputFile2.nextLine();
				var specLine = fullSpecLine;
				lineCounter++;

				var commentSplit = specLine.split(";"); // Comments (;...) omitted
				specLine = commentSplit[0].replaceAll("\\s+$", ""); // Remove end whitespace

				try {
					var line = specLine;
					scanLineSecondPass(line);
				} catch (AssemblerException e) {
					var error = getErrorMessage(lineCounter, fullSpecLine, e.getMessage());
					errorReport.add(error);
					resetBooleanValues();
					abortMnem = true;
					foundFormatHeader = true;
				}
			}
		} catch (FileNotFoundException e) {
			log.error("Specification file \"{}\" not found.", fileName);
			throw e;
		}

		currentlyParsing = State.MNEMONIC_DATA;
		// Run one last time with empty line to catch any error at end of mnemonic data
		// section
		try {
			var line = "";
			scanLineSecondPass(line);

		} catch (AssemblerException e) {
			var error = getErrorMessage(lineCounter, fullSpecLine, e.getMessage());
			errorReport.add(error);
			resetBooleanValues();
			abortMnem = true;
			foundFormatHeader = true;
		}

		if (!foundFormatHeader) {
			try {
				throw new AssemblerException("MnemonicData error: Mnemonic format missing for mnemonic \""
						+ currentMnemonic.getMnemonic() + "\".\n" + getMnemDataErrorMessage());
			} catch (AssemblerException e) {
				var error = getErrorMessage(lineCounter, fullSpecLine, e.getMessage());
				errorReport.add(error);
			}
		}

		// If missing sections in specification file
		if (!foundMnemData) {
			var missingSections = "\"mnemonicData\"";
			try {
				throw new AssemblerException("Section/s " + missingSections + " missing from specification file.");
			} catch (AssemblerException e) {
				var error = e.getMessage();
				errorReport.add(error);
			}
		}
	}

	private void scanLineFirstPass(String specLine) throws AssemblerException {
		// Section labels in specification file not case sensitive
		var lowerCaseLine = specLine.toLowerCase();

		if (lowerCaseLine.startsWith("architecture:")) {
			if (architectureDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			architectureDeclared = true;
			currentlyParsing = State.ARCHITECTURE;
		} else if (lowerCaseLine.startsWith("registers:")) {
			if (registersDeclared) {
				throw new AssemblerException("Registers section already declared.");
			}
			registersDeclared = true;

			currentlyParsing = State.REGISTERS;
		} else if (lowerCaseLine.startsWith("mnemonicdata:")) {
			if (mnemDataDeclared) {
				throw new AssemblerException("MnemonicData section already declared.");
			}
			mnemDataDeclared = true;
			currentlyParsing = State.MNEMONIC_DATA;
		} else if (lowerCaseLine.startsWith("instructionformat:")) {
			if (insFormatDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			insFormatDeclared = true;
			currentlyParsing = State.INSTRUCTION_FORMAT;
		} else if (lowerCaseLine.startsWith("assemblyoptree:")) {
			if (assemblyOpTreeDeclared) {
				throw new AssemblerException("AssemblyOpTree section already declared.");
			}
			assemblyOpTreeDeclared = true;
			currentlyParsing = State.ASSEMBLY_OP_TREE;
		} else if (lowerCaseLine.startsWith("endian:")) {
			if (endianDeclared) {
				throw new AssemblerException("Endian section already declared.");
			}
			endianDeclared = true;
			currentlyParsing = State.ENDIAN;
		} else if (lowerCaseLine.startsWith("minaddressableunit:")) {
			if (minAdrUnitDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			minAdrUnitDeclared = true;
			currentlyParsing = State.MIN_ADDRESSABLE_UNIT;
		} else if (currentlyParsing != null) {
			switch (currentlyParsing) {
			case ARCHITECTURE:
				analyseArchitecture(specLine);
				break;
			case REGISTERS:
				analyseRegisters(specLine);
				break;
			case INSTRUCTION_FORMAT:
				analyseInstructionFormat(specLine);
				break;
			case ASSEMBLY_OP_TREE:
				analyseAssemblyOpTree(specLine);
				break;
			case ENDIAN:
				analyseEndian(specLine);
				break;
			case MIN_ADDRESSABLE_UNIT:
				analyseMinAddressableUnit(specLine);
				break;
			default:
				// SKip
			}
		} else if (specLine.trim().length() != 0) {
			throw new AssemblerException("No section header.");
		}
	}

	private void scanLineSecondPass(String specLine) throws AssemblerException {
		// Section labels in specification file not case sensitive
		var lowerCaseLine = specLine.toLowerCase();

		if (lowerCaseLine.startsWith("architecture:")) {
			if (architectureDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			architectureDeclared = true;
			currentlyParsing = State.ARCHITECTURE;
		} else if (lowerCaseLine.startsWith("registers:")) {
			if (registersDeclared) {
				throw new AssemblerException("Registers section already declared.");
			}
			registersDeclared = true;

			currentlyParsing = State.REGISTERS;
		} else if (lowerCaseLine.startsWith("mnemonicdata:")) {
			if (mnemDataDeclared) {
				throw new AssemblerException("MnemonicData section already declared.");
			}
			mnemDataDeclared = true;
			currentlyParsing = State.MNEMONIC_DATA;
		} else if (lowerCaseLine.startsWith("instructionformat:")) {
			if (insFormatDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			insFormatDeclared = true;
			currentlyParsing = State.INSTRUCTION_FORMAT;
		} else if (lowerCaseLine.startsWith("assemblyoptree:")) {
			if (assemblyOpTreeDeclared) {
				throw new AssemblerException("AssemblyOpTree section already declared.");
			}
			assemblyOpTreeDeclared = true;
			currentlyParsing = State.ASSEMBLY_OP_TREE;
		} else if (lowerCaseLine.startsWith("endian:")) {
			if (endianDeclared) {
				throw new AssemblerException("Endian section already declared.");
			}
			endianDeclared = true;
			currentlyParsing = State.ENDIAN;
		} else if (lowerCaseLine.startsWith("minaddressableunit:")) {
			if (minAdrUnitDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			minAdrUnitDeclared = true;
			currentlyParsing = State.MIN_ADDRESSABLE_UNIT;
		} else if (currentlyParsing != null) {
			switch (currentlyParsing) {
			case MNEMONIC_DATA:
				analyseMnemonicData(specLine);
				break;
			default:
				// SKip
			}
		} else if (specLine.trim().length() != 0) {
			throw new AssemblerException("No section header.");
		}
	}

	///////////////////////////////////////
	private void analyseArchitecture(String line) throws AssemblerException {
		if (Strings.isNullOrEmpty(line)) {
			return;
		}

		if (foundArchitecture) {
			throw new AssemblerException("Architecture error: Architecture name already specified.");
		}

		foundArchitecture = true;
		specFile.setArchitecture(line.trim());
	}

	private void analyseAssemblyOpTree(String line) throws AssemblerException {
		if (Strings.isNullOrEmpty(line)) {
			return;
		}

		foundAssemblyOpTree = true;
		line = line.trim();

		var legitAssemblyOpTreeExp = Pattern.matches("[^:]+:.+", line);

		if (!legitAssemblyOpTreeExp) {
			throw new AssemblerException(
					"AssemblyOpTree error: Line syntax error, expected format <node> : <expression>");
		}

		var assemblyOpTree = specFile.getAssemblyOpTree();
		var assemblyOpTreeTokens = line.split("[^A-Za-z0-9]+");

		Collections.addAll(assemblyOpTree.getAssemblyOpTreeTokens(), assemblyOpTreeTokens);

		var colonSplit = line.split(":", 2);
		var node = colonSplit[0].trim();

		if (node.equals("LABEL") || node.equals("INT") || node.equals("HEX")) {
			throw new AssemblerException(
					"AssemblyOpTree error: Node can not be keyword \"LABEL\", \"INT\" or \"HEX\".");
		}

		var legitNode = Pattern.matches("[a-zA-Z0-9]+", node);

		if (!legitNode) {
			throw new AssemblerException(
					"AssemblyOpTree error: Node error, should be alphanumeric token, expected format <node> : <expression>");
		}

		var expression = colonSplit[1].trim();

		// First entry must be root term
		if (firstAssemblyOpTreeEntry || node.equals(rootOpTreeEntry)) {

			// Legit assemblyOpTree expression:
			// (letters|numbers)+ space* colon space* (!(space|colon))+ (space*
			// (!(space|colon))+)*
			var legitRootExp = Pattern.matches("[^\\s]+(\\s*[^\\s]+)*", expression);

			if (!legitRootExp) {
				throw new AssemblerException("AssemblyOpTree error: Root expression syntax error.");
			}

			if (firstAssemblyOpTreeEntry) {
				rootOpTreeEntry = node;
				assemblyOpTree.setRootToken(node);
				firstAssemblyOpTreeEntry = false;
			}
		}

		else {
			// Single token
			var legitNonRootExp = Pattern.matches("[^\\s]+", expression);

			if (!legitNonRootExp) {
				throw new AssemblerException(
						"AssemblyOpTree error: Non root expressions should only consist of a single token.");
			} else if (expression.charAt(expression.length() - 1) == '*'
					|| expression.charAt(expression.length() - 1) == '+'
					|| expression.charAt(expression.length() - 1) == '?') {
				throw new AssemblerException(
						"AssemblyOpTree error: Wildcards (\"*\", \"+\" or \"?\") can only be applied to tokens in root node expression (\""
								+ specFile.getAssemblyOpTree().getRootToken() + "\").");
			}
		}

		assemblyOpTree.getAssemblyOpTreeTokens().add(node);
		assemblyOpTree.getAssemblyOpTreeTokens().add(expression);

		// If node already exists in tree, then add to existing node list, else put
		// node in hash
		var list = assemblyOpTree.getAssemblyOpTreeHash().get(node);

		if (list != null) {
			list.add(expression);
		} else {
			var termsList = new ArrayList<String>();
			termsList.add(expression);
			assemblyOpTree.getAssemblyOpTreeHash().put(node, termsList);
		}
	}

	private void analyseEndian(String line) throws AssemblerException {
		if (Strings.isNullOrEmpty(line)) {
			return;
		}

		if (foundEndian) {
			throw new AssemblerException("Endian error: Endian already specified.");
		}

		foundEndian = true;
		line = line.trim();
		line = line.toLowerCase();

		if (line.equals("big")) {
			specFile.setEndian("big");
		} else if (line.equals("little")) {
			specFile.setEndian("little");
		} else {
			throw new AssemblerException("Endian error: Endian not recognised, \"big\" or \"little\" expected.");
		}
	}

	private void analyseGlobalFieldEncodings(String line) throws AssemblerException {
		line = line.trim();

		// Legit global encoding expression:
		// alphanumeric+ space* equals space* alphanumeric+
		// (space* comma space* alphanumeric+ space* equals space*
		// alphanumeric+)*
		var legitGlobalEncodings = Pattern
				.matches("[a-zA-Z0-9]+\\s*=\\s*[a-zA-Z0-9]+(\\s*,\\s*[a-zA-Z0-9]+\\s*=\\s*[a-zA-Z0-9]+)*", line);

		if (!legitGlobalEncodings) {
			abortMnem = true;
			throw new AssemblerException(
					"MnemonicData error: Global encodings syntax error, <fieldName>=<value><B/H/I> expected.");
		}

		// Legit global encodings so omit unnecessary spaces
		line = line.replaceAll("\\s+", "");
		var tokens = line.split(",");

		for (String token : tokens) {
			var elements = token.split("=");
			var field = elements[0];
			var valueAndBase = elements[1];
			var binary = getBinaryFromBase(valueAndBase);
			currentMnemonic.getGlobalFieldEncodingHash().put(field, binary);
		}

		currentMnemonic.setRawGlobalFieldEncodingString(line);
	}

	private void analyseInstructionFormat(String line) throws AssemblerException {
		if (Strings.isNullOrEmpty(line)) {
			return;
		}

		foundInsFormat = true;
		line = line.trim();

		// Legit instruction format:
		// (!(space|colon))+ space* colon space* (letters|numbers)+ openBracket
		// 0-9+ closeBracket
		// (space* (letter|numbers)+ openBracket 0-9+ closeBracket)*
		var validInsFormat = Pattern.matches("[^\\s:]+\\s*:\\s*[a-zA-Z0-9]+\\([0-9]+\\)(\\s*[a-zA-Z0-9]+\\([0-9]+\\))*",
				line);

		if (!validInsFormat) {
			throw new AssemblerException(
					"InstructionFormat error: Syntax error, <instructionName> : <fieldName>(<bitLength>) expected. For example:\n"
							+ "\nopcode : op(6) d(1) s(1)");
		}

		var insF = new InstructionFormat();
		var tokens = line.split(":");
		var insName = tokens[0].trim();
		var fieldsAndValues = tokens[1].trim();
		var fieldTokens = fieldsAndValues.split("\\s+");

		for (String field : fieldTokens) {
			var fieldAndSize = field.split("\\(|\\)");
			var fieldName = fieldAndSize[0];
			var bitSize = Integer.parseInt(fieldAndSize[1]);
			if (bitSize == 0) {
				throw new AssemblerException("InstructionFormat error: Can not have 0 bit field length.");
			}
			if (insF.getFields().contains(fieldName)) {
				throw new AssemblerException(
						"InstructionFormat error: Field \"" + fieldName + "\" defined multiple times in instruction.");
			}
			insF.getFields().add(fieldName);
			insF.getFieldBitHash().put(fieldName, bitSize);
		}

		insF.setInstructionName(insName);
		insF.setRawLineString(line.trim());

		if (specFile.getInstructionFormatHash().get(insName) != null) {
			throw new AssemblerException("InstructionFormat error: Instruction \"" + insName + "\" already defined");
		}

		specFile.getInstructionFormatHash().put(insName, insF);
	}

	private void analyseMinAddressableUnit(String line) throws AssemblerException {
		if (Strings.isNullOrEmpty(line)) {
			return;
		}

		if (foundMinAdrUnit) {
			throw new AssemblerException("MinAddressableUnit error: Minimum addressable unit already specified.");
		}

		foundMinAdrUnit = true;
		line = line.trim();

		var legitMinAdrUnit = Pattern.matches("[0-9]+", line);

		if (!legitMinAdrUnit) {
			throw new AssemblerException("MinAddressableUnit error: Syntax error, single integer expected.");
		}

		var minAdrUnit = Integer.parseInt(line);

		if (minAdrUnit <= 0) {
			throw new AssemblerException("MinAddressableUnit error: Minimum addressable unit must be greater than 0.");
		}

		specFile.setMinAdrUnit(minAdrUnit);
	}

	private void analyseMnemName(String line) throws AssemblerException {
		// Reset boolean values for new mnemonic
		resetBooleanValues();
		var mnem = line.trim();

		// Legit mnemonic name expression:
		// (!space)+
		var legitMnemName = Pattern.matches("[^\\s]+", mnem);

		if (!legitMnemName) {
			abortMnem = true;
			throw new AssemblerException(
					"MnemonicData error: Mnemonic name syntax error, should only be single token (no spaces).");
		}

		currentMnemonic = new Mnemonic();
		currentMnemonic.setMnemonic(mnem);

		if (specFile.getMnemonicTable().get(mnem) != null) {
			throw new AssemblerException("MnemonicData error: Mnemonic name \"" + mnem + "\" already defined.");
		}

		// Put mnemonic data in mnemonic hash table
		specFile.getMnemonicTable().put(mnem, currentMnemonic);
	}

	private void analyseMnemonicData(String line) throws AssemblerException {
		try {
			currentMnemonic.addToRawLines(line);
		} catch (NullPointerException e) {
		}

		if (Strings.isNullOrEmpty(line)) {
			emptyLine = true;

			if (abortMnem) {
				return;
			}

			if (atOperandFieldEncodings || atLocalFieldEncodings || atInsFormat) {
				checkWhatLineExpected();
			}
			return;
		}

		foundMnemData = true;

		// New mnemonic (no whitespace at beginning)
		if (Pattern.matches("[^\t\\s].*", line) && emptyLine && foundFormatHeader && !atOperandFieldEncodings
				&& !atLocalFieldEncodings && !atInsFormat) {
			emptyLine = false;
			analyseMnemName(line);
			currentMnemonic.addToRawLines(line);
		}

		else if (abortMnem) {
		} else if (currentMnemonic == null) {
			abortMnem = true;
			throw new AssemblerException("MnemonicData error: Mnemonic name not declared.");
		}

		// Global field encodings (starts with tab and not passed an empty line)
		else if (Pattern.matches("\t[^\t\\s].*", line) && !emptyLine && !doneGlobalEncodings) {
			analyseGlobalFieldEncodings(line);
			doneGlobalEncodings = true;
		}

		// Operand format (starts with tab and empty line passed)
		else if (Pattern.matches("\t[^\t\\s].*", line)) {

			if (!emptyLine) {
				checkWhatLineExpected();
			}
			emptyLine = false;
			analyseOperandFormat(line);
			atOperandFieldEncodings = true;
			foundFormatHeader = true;

			try {
				currentMnemFormat.addToRawLineString(line);
			} catch (NullPointerException e) {
			}
		}

		// Operand format data (starts with double tab and empty line passed)
		else if (Pattern.matches("\t\t[^\t\\s].*", line)
				&& (atOperandFieldEncodings || atLocalFieldEncodings || atInsFormat)) {

			try {
				currentMnemFormat.addToRawLineString(line);
			} catch (NullPointerException e) {
			}

			analyseOperandFormatData(line);
		} else {
			checkWhatLineExpected();
		}
	}

	private void analyseOperandFormat(String line) throws AssemblerException {
		line = line.trim();

		var mnemFormatSplit = line.split("\\s+");
		var mnemFormatList = new ArrayList<String>();

		for (String formatTerm : mnemFormatSplit) {
			formatTerm = formatTerm.replaceAll("^,+", "");
			formatTerm = formatTerm.replaceAll(",+$", "");

			if (!formatTerm.isEmpty()) {
				mnemFormatList.add(formatTerm);
			}
		}

		// Check format token has been defined somewhere in tree
		var assemblyOpTreeTokens = specFile.getAssemblyOpTree().getAssemblyOpTreeTokens();

		for (String formatToken : mnemFormatList) {
			if (!assemblyOpTreeTokens.contains(formatToken)) {
				abortMnem = true;
				throw new AssemblerException("MnemonicData error: Operand format token \"" + formatToken
						+ "\" not found in AssemblyOpTree.");
			}
		}

		currentMnemFormat = new OperandFormat();
		currentMnemFormat.setMnemFormat(line);
		currentMnemonic.getOperandsFormats().add(line);

		if (currentMnemonic.getOperandFormatHash().get(line) != null) {
			throw new AssemblerException("MnemonicData error: Operand format \"" + line
					+ "\" already defined for mnemonic \"" + currentMnemonic.getMnemonic() + "\".");
		}

		currentMnemonic.getOperandFormatHash().put(line, currentMnemFormat);
	}

	private void analyseOperandFormatData(String line) throws AssemblerException {
		if (atOperandFieldEncodings) {
			line = line.trim();

			// If line is "--" then there are no operand field encodings
			if (!line.equals("--")) {
				currentMnemFormat.setOperandFieldEncodings(line);
			}

			if (duplicateFieldDefined(line)) {
				throw new AssemblerException("Duplicate field defined.");
			}

			atOperandFieldEncodings = false;
			atLocalFieldEncodings = true;
		}

		else if (atLocalFieldEncodings) {
			line = line.trim();

			// If line is "--" then there are no local encodings
			if (!line.equals("--")) {

				// Legit local encoding expression:
				// (!(space|equals|comma))+ space* equals space*
				// (!(space|equals|comma))+
				// (space* comma space* (!(space|equals|comma))+ space* equals
				// space* (!(space|equals|comma))+)*
				var legitLocalEncodings = Pattern.matches(
						"[A-Za-z0-9]+\\s*=\\s*[A-Za-z0-9]+(\\s*,\\s*[A-Za-z0-9]+\\s*=\\s*[A-Za-z0-9]+)*", line);

				if (!legitLocalEncodings) {
					abortMnem = true;
					throw new AssemblerException("MnemonicData error: Local encodings syntax error,"
							+ "\n<fieldName>=<value><B/H/I> or \"--\" (if no local encodings) expected.");
				}

				// Legit local field encodings so omit unnecessary spaces
				line = line.replaceAll("\\s+", "");
				var tokens = line.split(",");

				for (String token : tokens) {
					var elements = token.split("=");
					var field = elements[0];
					var valueAndBase = elements[1];
					var binary = getBinaryFromBase(valueAndBase);
					currentMnemFormat.getFieldBitHash().put(field, binary);
				}
			}
			atLocalFieldEncodings = false;
			atInsFormat = true;
		}

		else if (atInsFormat) {
			line = line.trim();
			var tokens = line.split("\\s+");
			Collections.addAll(currentMnemFormat.getInstructionFormat(), tokens);
			endOfOperandFormatBlockErrorCheck();
			atInsFormat = false;
		}
	}

	private void analyseRegisters(String line) throws AssemblerException {
		if (Strings.isNullOrEmpty(line)) {
			return;
		}

		line = line.trim();

		// Valid register expression:
		// (!space)+ space+ (!space)+
		var legitRegExp = Pattern.matches("[^\\s]+\\s+[^\\s]+", line);

		if (!legitRegExp) {
			throw new AssemblerException(
					"Registers error: Syntax error, <registerName> <value><B/H/I> expected. For example:\n" + "\n"
							+ "eax    000B");
		}

		var tokens = line.split("\\s+");

		var regName = tokens[0];
		var valueAndBase = tokens[1];
		var regValue = getBinaryFromBase(valueAndBase);

		if (specFile.getRegisterHash().get(regName) != null) {
			throw new AssemblerException("Registers error: Register \"" + regName + "\" already defined.");
		}

		specFile.getRegisterHash().put(regName, regValue);
	}

	private void checkWhatLineExpected() throws AssemblerException {
		abortMnem = true;

		if (atOperandFieldEncodings) {
			abortMnem = true;
			throw new AssemblerException(
					"MnemonicData error: Line format or indentation error, operand field encodings line expected. Line should begin with two tabs.\n"
							+ getMnemDataErrorMessage());
		}

		else if (atLocalFieldEncodings) {
			throw new AssemblerException(
					"MnemonicData error: Line format or indentation error, local field encodings line expected. Line should begin with two tabs.\n"
							+ getMnemDataErrorMessage());
		}

		else if (atInsFormat) {
			throw new AssemblerException(
					"MnemonicData error: Line format or indentation error, instruction format line expected. Line should begin with two tabs.\n"
							+ getMnemDataErrorMessage());
		}

		else if (!emptyLine) {
			throw new AssemblerException(
					"MnemonicData error: Line format error, empty line expected.\n" + getMnemDataErrorMessage());
		}

		else if (!foundFormatHeader) {
			throw new AssemblerException(
					"MnemonicData error: Line format or indentation error, operand format line expected.\nOperand format missing for mnemonic \""
							+ currentMnemonic.getMnemonic() + "\".\n" + getMnemDataErrorMessage());
		} else {
			throw new AssemblerException("MnemonicData error: Line format or indentation error.");
		}
	}

	private boolean duplicateFieldDefined(String line) {

		var splitLine = line.split("(?=[^a-zA-Z0-9])|(?<=[^a-zA-Z0-9])");
		var test = new ArrayList<String>();

		for (String str : splitLine) {
			if (Assembler.isAlphaNumeric(str)) {
				test.add(str);
			}
		}

		for (var j = 0; j < test.size(); j++) {
			for (var k = j + 1; k < test.size(); k++) {
				if (test.get(k).equals(test.get(j))) {
					return true;
				}
			}
		}
		return false;
	}

	private void endOfOperandFormatBlockErrorCheck() throws AssemblerException {

		// Error checking after all lines of an operandFormat declaration have been read

		var instructionFormat = currentMnemFormat.getInstructionFormat();
		var totalBits = 0;

		for (String instruction : instructionFormat) {
			var insFormat = specFile.getInstructionFormatHash().get(instruction);

			if (insFormat == null) {
				abortMnem = true;
				throw new AssemblerException(
						currentMnemFormat.getRawLinesString() + "\nMnemonicData error: Instruction \"" + instruction
								+ "\" not defined in instructionFormat section.");
			}

			var instructions = insFormat.getFields();

			for (String field : instructions) {
				int bits = insFormat.getFieldBitHash().get(field);
				totalBits += bits;

				// Field defined in global encodings
				if (currentMnemonic.getGlobalFieldEncodingHash().get(field) != null) {
					var field1 = currentMnemonic.getGlobalFieldEncodingHash().get(field);
					var noOfBits = field1.length();

					if (noOfBits > bits) {
						abortMnem = true;
						throw new AssemblerException(
								currentMnemonic.getRawLinesString() + "\nMnemonicData error: Encoding for field \""
										+ field + "\" in \"" + currentMnemonic.getMnemonic() + "\" global encodings ("
										+ currentMnemonic.getRawGlobalFieldEncodingString() + ")\nexceeds expected "
										+ bits + " bits in instruction format \"" + instruction + "\" ("
										+ insFormat.getRawLineString() + ").");
					}
				}

				// Field defined in local encodings
				else if (currentMnemFormat.getFieldBitHash().get(field) != null) {
					var field1 = currentMnemFormat.getFieldBitHash().get(field);
					var noOfBits = field1.length();

					if (noOfBits > bits) {
						abortMnem = true;
						throw new AssemblerException(currentMnemFormat.getRawLinesString()
								+ "\nMnemonicData error: Encoding for field \"" + field + "\" in local encodings for \""
								+ currentMnemonic.getMnemonic() + "\" format \"" + currentMnemFormat.getMnemFormat()
								+ "\"\nexceeds expected " + bits + " bits in instruction format \"" + instruction
								+ "\" (" + insFormat.getRawLineString() + ").");
					}
				}

				// Field defined in operand encodings
				else if (existsInOperandFieldEncodings(currentMnemFormat.getOperandFieldEncodings(), field)) {

				} else {
					abortMnem = true;
					throw new AssemblerException(currentMnemonic.getRawLinesString() + "\nMnemonicData error: Field \""
							+ field + "\" in instruction format \"" + instruction + "\" ("
							+ insFormat.getRawLineString() + ")\nnot found within global \""
							+ currentMnemonic.getMnemonic() + "\" encodings ("
							+ currentMnemonic.getRawGlobalFieldEncodingString() + ") or in \""
							+ currentMnemonic.getMnemonic() + "\" format \"" + currentMnemFormat.getMnemFormat()
							+ "\".");
				}
			}
		}

		var minAdrUnit = specFile.getMinAdrUnit();

		// If total instruction size is not divisible by minimum addressable unit
		if (totalBits % minAdrUnit != 0) {
			throw new AssemblerException(
					currentMnemFormat.getRawLinesString() + "\nMnemonicData error: Total instruction size (" + totalBits
							+ " bits) should be divisable by the minimum addressable unit (" + minAdrUnit + ")");
		}
	}

	private boolean existsInOperandFieldEncodings(String operandFieldEncodings, String field) {

		var operandFieldEncodingTokens = operandFieldEncodings.split("[^a-zA-Z0-9]+");

		for (String field1 : operandFieldEncodingTokens) {
			if (field1.equals(field)) {
				return true;
			}
		}
		return false;
	}

	private String getBinaryFromBase(String valueAndBase) throws AssemblerException {
		var base = valueAndBase.charAt(valueAndBase.length() - 1);
		var value = valueAndBase.substring(0, valueAndBase.length() - 1);

		// Binary
		if (base == 'B') {
			if (value.isEmpty()) {
				throw new AssemblerException(
						"Value error: Syntax error, <value><B/H/I> expected.\nBinary value missing.");
			}
			if (!isBinary(value)) {
				throw new AssemblerException(
						MessageFormat.format("Value error: \"{0}\" is not a valid binary value.", value));
			}
		}

		// Hex
		else if (base == 'H') {
			if (value.isEmpty()) {
				throw new AssemblerException(
						"Value error: Syntax error, <value><B/H/I> expected.\n" + "Hex value missing.");
			}

			try {
				value = Assembler.hexToBinary(value);
			} catch (NumberFormatException e) {
				throw new AssemblerException(
						MessageFormat.format("Value error: \"{0}\" is not a valid hex value.", value));
			}
		}

		// Integer
		else if (base == 'I') {
			if (value.isEmpty()) {
				throw new AssemblerException(
						"Value error: Syntax error, <value><B/H/I> expected.\nInteger value missing.");
			}

			try {
				value = Assembler.intToBinary(value);
			} catch (NumberFormatException e) {
				throw new AssemblerException(
						MessageFormat.format("Value error: \"{0}\" is not a valid integer.", value));
			}
		} else {
			throw new AssemblerException(MessageFormat.format(
					"Value error: Syntax error, <value><B/H/I> expected.\nLast character of second string (\"{0}\") should indicate data type (\"B\", \"H\" or \"I\").\nB indicates value is binary, H indicates hexadecimal and I indicates integer.",
					valueAndBase));
		}

		return value;
	}

	private String getErrorMessage(int lineCounter, String fullSpecLine, String message) {
		var msg = new StringBuilder("------------------------------------------\n");
		msg.append("Exception at line ").append(lineCounter).append(" :\n");
		msg.append("\n");
		msg.append(fullSpecLine).append("\n");
		msg.append("------------------------------------------\n");
		msg.append("\n");
		msg.append(message).append("\n\n");

		return msg.toString();
	}

	private String getMnemDataErrorMessage() {
		var rawLines = currentMnemonic.getRawLines();
		var noOfLines = rawLines.size();
		var maxLineLength = 0;
		var msg = new StringBuilder();

		for (String str : rawLines) {
			str = str.replaceAll("\\s+$", "");
			if (str.length() > maxLineLength) {
				maxLineLength = str.length();
			}
			msg.append("\n").append(str);
		}

		var lastLineLength = rawLines.get(noOfLines - 1).replaceAll("\\s+$", "").length();
		var noOfSpaces = 0;
		var whiteSpace = new StringBuilder("\t\t\t");

		if (lastLineLength == 0) {
			noOfSpaces = maxLineLength;
		} else {
			noOfSpaces = maxLineLength - lastLineLength;
		}

		for (; noOfSpaces > 0; noOfSpaces -= 1) {
			whiteSpace.append(" ");
		}

		msg.append(whiteSpace.toString()).append("<---");

		return msg.toString();
	}

	private boolean isBinary(String s) {

		var pattern = "[0-1]*$";

		if (s.matches(pattern)) {
			return true;
		}

		return false;
	}

	private void resetBooleanValues() {
		abortMnem = false;
		doneGlobalEncodings = false;
		emptyLine = false;
		foundFormatHeader = false;
		atOperandFieldEncodings = false;
		atLocalFieldEncodings = false;
		atInsFormat = false;
		currentMnemonic = null;
	}

	private void resetDeclarationBooleans() {
		architectureDeclared = false;
		registersDeclared = false;
		insFormatDeclared = false;
		assemblyOpTreeDeclared = false;
		endianDeclared = false;
		minAdrUnitDeclared = false;
		mnemDataDeclared = false;
	}

}
