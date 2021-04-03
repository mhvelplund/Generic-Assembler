package dk.sar.gasm;

/**
 * Eddie Graham
 * 1101301g
 * Individual Project 4
 * Supervisor: John T O'Donnell
 */

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Scanner;
import java.util.regex.Pattern;

import com.google.common.base.Strings;

import lombok.extern.slf4j.Slf4j;

/**
 * This class parses both the specification and assembly files and stores the
 * information in the data source (DataSource.java).
 *
 * @author Eddie Graham
 */
@Slf4j
public class FileParser {
	private boolean architecture, registers, mnemonicData, instructionFormat, assemblyOpTree, endian,
			minAddressableUnit;

	private boolean architectureDeclared, registersDeclared, mnemDataDeclared, insFormatDeclared,
			assemblyOpTreeDeclared, endianDeclared, minAdrUnitDeclared;

	private OperandFormat currentMnemFormat;
	private Mnemonic currentMnemonic;
	private DataSource data;
	private boolean doneGlobalEncodings, emptyLine, abortMnem;
	private List<String> errorReport;
	private boolean firstAssemblyOpTreeEntry;
	private boolean foundArchitecture, foundMnemData, foundInsFormat, foundAssemblyOpTree, foundEndian, foundMinAdrUnit;
	private boolean foundFormatHeader, atOperandFieldEncodings, atLocalFieldEncodings, atInsFormat;
	private String rootOpTreeEntry;

	/**
	 * Constructor for class, initialises variables and calls methods which scan
	 * both files ("scanAssemblyFile(assemblyFile)" and "scanSpecFile(specFile)").
	 *
	 * @param specFile
	 * @param assemblyFile
	 * @throws FileNotFoundException
	 * @throws FileParserException
	 */
	public FileParser(String specFile, String assemblyFile) throws FileNotFoundException, FileParserException {
		data = new DataSource();

		errorReport = new ArrayList<>();

		architecture = false;
		registers = false;
		mnemonicData = false;
		instructionFormat = false;
		assemblyOpTree = false;
		endian = false;
		minAddressableUnit = false;

		foundArchitecture = false;
		foundMnemData = false;
		foundInsFormat = false;
		foundAssemblyOpTree = false;
		foundEndian = false;
		foundMinAdrUnit = false;

		architectureDeclared = false;
		registersDeclared = false;
		mnemDataDeclared = false;
		insFormatDeclared = false;
		assemblyOpTreeDeclared = false;
		endianDeclared = false;
		minAdrUnitDeclared = false;

		doneGlobalEncodings = false;
		emptyLine = true;
		abortMnem = false;

		foundFormatHeader = true;
		atOperandFieldEncodings = false;
		atLocalFieldEncodings = false;
		atInsFormat = false;

		firstAssemblyOpTreeEntry = true;
		rootOpTreeEntry = "";

		currentMnemonic = null;
		currentMnemFormat = null;

		scan(assemblyFile, specFile);
	}

	private void analyseArchitecture(String line) throws AssemblerException {
		if (Strings.isNullOrEmpty(line)) {
			return;
		}

		if (foundArchitecture) {
			throw new AssemblerException("Architecture error: Architecture name already specified.");
		}

		foundArchitecture = true;
		data.setArchitecture(line.trim());
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

		var assemblyOpTree = data.getAssemblyOpTree();
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
								+ data.getAssemblyOpTree().getRootToken() + "\").");
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
			data.setEndian("big");
		} else if (line.equals("little")) {
			data.setEndian("little");
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

		if (data.getInstructionFormatHash().get(insName) != null) {
			throw new AssemblerException("InstructionFormat error: Instruction \"" + insName + "\" already defined");
		}

		data.getInstructionFormatHash().put(insName, insF);
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

		data.setMinAdrUnit(minAdrUnit);
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

		if (data.getMnemonicTable().get(mnem) != null) {
			throw new AssemblerException("MnemonicData error: Mnemonic name \"" + mnem + "\" already defined.");
		}

		// Put mnemonic data in mnemonic hash table
		data.getMnemonicTable().put(mnem, currentMnemonic);
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
		var assemblyOpTreeTokens = data.getAssemblyOpTree().getAssemblyOpTreeTokens();

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

		if (data.getRegisterHash().get(regName) != null) {
			throw new AssemblerException("Registers error: Register \"" + regName + "\" already defined.");
		}

		data.getRegisterHash().put(regName, regValue);
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
			var insFormat = data.getInstructionFormatHash().get(instruction);

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

		var minAdrUnit = data.getMinAdrUnit();

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

	public DataSource getData() {
		return data;
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

	private void scan(String assemblyFile, String specFile) throws FileNotFoundException, FileParserException {

		scanAssemblyFile(assemblyFile);
		scanSpecFile(specFile);

		if (!errorReport.isEmpty()) {
			throw new FileParserException("Error in specification file, see \"spec_error_report.txt\".", errorReport);
		} else {
			errorReport.add("No errors found within specification file.");
		}

		Assembler.writeLinesToFile("spec_error_report.txt", errorReport);
	}

	private void scanAssemblyFile(String fileName) throws FileNotFoundException {
		try (var inputFile = new Scanner(new FileInputStream(fileName))) {
			while (inputFile.hasNextLine()) {
				var line = inputFile.nextLine();
				data.getAssemblyCode().add(line);
			}
		} catch (FileNotFoundException e) {
			log.error("Assembly file \"{}\" not found.", fileName);
			throw e;
		}
	}

	private void scanLine(String specLine, boolean ignoreArchitecture, boolean ignoreRegisters,
			boolean ignoreMnemonicData, boolean ignoreInstructionFormat, boolean ignoreAssemblyOpTree,
			boolean ignoreEndian, boolean ignoreMinAddressableUnit, boolean ignoreInstructionSize)
			throws AssemblerException {

		// Section labels in specification file not case sensitive
		var lowerCaseLine = specLine.toLowerCase();

		if (lowerCaseLine.startsWith("architecture:")) {
			if (architectureDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			architectureDeclared = true;
			setBooleanValues(true, false, false, false, false, false, false);
		}

		else if (lowerCaseLine.startsWith("registers:")) {
			if (registersDeclared) {
				throw new AssemblerException("Registers section already declared.");
			}
			registersDeclared = true;
			setBooleanValues(false, true, false, false, false, false, false);
		}

		else if (lowerCaseLine.startsWith("mnemonicdata:")) {
			if (mnemDataDeclared) {
				throw new AssemblerException("MnemonicData section already declared.");
			}
			mnemDataDeclared = true;
			setBooleanValues(false, false, true, false, false, false, false);
		}

		else if (lowerCaseLine.startsWith("instructionformat:")) {
			if (insFormatDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			insFormatDeclared = true;
			setBooleanValues(false, false, false, true, false, false, false);
		}

		else if (lowerCaseLine.startsWith("assemblyoptree:")) {
			if (assemblyOpTreeDeclared) {
				throw new AssemblerException("AssemblyOpTree section already declared.");
			}
			assemblyOpTreeDeclared = true;
			setBooleanValues(false, false, false, false, true, false, false);
		}

		else if (lowerCaseLine.startsWith("endian:")) {
			if (endianDeclared) {
				throw new AssemblerException("Endian section already declared.");
			}
			endianDeclared = true;
			setBooleanValues(false, false, false, false, false, true, false);
		}

		else if (lowerCaseLine.startsWith("minaddressableunit:")) {
			if (minAdrUnitDeclared) {
				throw new AssemblerException("Architecture section already declared.");
			}
			minAdrUnitDeclared = true;
			setBooleanValues(false, false, false, false, false, false, true);
		}

		else if (architecture) {
			if (!ignoreArchitecture) {
				analyseArchitecture(specLine);
			}
		}

		else if (registers) {
			if (!ignoreRegisters) {
				analyseRegisters(specLine);
			}
		}

		else if (mnemonicData) {
			if (!ignoreMnemonicData) {
				analyseMnemonicData(specLine);
			}
		}

		else if (instructionFormat) {
			if (!ignoreInstructionFormat) {
				analyseInstructionFormat(specLine);
			}
		}

		else if (assemblyOpTree) {
			if (!ignoreAssemblyOpTree) {
				analyseAssemblyOpTree(specLine);
			}
		}

		else if (endian) {
			if (!ignoreEndian) {
				analyseEndian(specLine);
			}
		}

		else if (minAddressableUnit) {
			if (!ignoreMinAddressableUnit) {
				analyseMinAddressableUnit(specLine);
			}
		} else if (specLine.trim().length() != 0) {
			throw new AssemblerException("No section header.");
		}
	}

	private void scanSpecFile(String fileName) throws FileNotFoundException, FileParserException {
		// Two scanners as file is parsed twice. MnemonicData is analysed last for
		// error checking

		var lineCounter = 0;

		try (var inputFile = new Scanner(new FileInputStream(fileName))) {

			while (inputFile.hasNextLine()) {
				var fullSpecLine = inputFile.nextLine();
				var specLine = fullSpecLine;
				lineCounter++;

				// Comments (;...) omitted
				var commentSplit = specLine.split(";");

				try {
					specLine = commentSplit[0];
				} catch (ArrayIndexOutOfBoundsException e) {
					specLine = "";
				}

				// Remove end whitespace
				specLine = specLine.replaceAll("\\s+$", "");

				try {
					scanLine(specLine, false, false, true, false, false, false, false, false);
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
				var commentSplit = specLine.split(";");

				try {
					specLine = commentSplit[0];
				} catch (ArrayIndexOutOfBoundsException e) {
					specLine = "";
				}

				specLine = specLine.replaceAll("\\s+$", "");

				try {
					scanLine(specLine, true, true, false, true, true, true, true, true);
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

		mnemonicData = true;
		// Run one last time with empty line to catch any error at end of mnemonic data
		// section
		try {
			scanLine("", true, true, false, true, true, true, true, true);

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

	private void setBooleanValues(boolean architecture, boolean registers, boolean mnemonicData,
			boolean instructionFormat, boolean assemblyOpTree, boolean endian, boolean minAddressableUnit) {
		this.architecture = architecture;
		this.registers = registers;
		this.mnemonicData = mnemonicData;
		this.instructionFormat = instructionFormat;
		this.assemblyOpTree = assemblyOpTree;
		this.endian = endian;
		this.minAddressableUnit = minAddressableUnit;
	}
}
