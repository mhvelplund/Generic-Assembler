package dk.sar.gasm;

/**
 * Eddie Graham
 * 1101301g
 * Individual Project 4
 * Supervisor: John T O'Donnell
 */

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.regex.Pattern;

import dk.sar.gasm.data.DataSource;
import dk.sar.gasm.data.Mnemonic;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * A two pass assembler.
 *
 * @author Eddie Graham
 */
@Slf4j
@SuppressWarnings("deprecation")
public class Assembler {
	public static String binaryFormatted(String binary, int bits) {
		var initialLength = binary.length();
		var zerosNeeded = bits - initialLength;
		var zeros = new StringBuilder();

		for (; zerosNeeded > 0; zerosNeeded -= 1) {
			zeros.append("0");
		}

		var finalString = zeros.append(binary).toString();

		return finalString;
	}

	public static String binaryFromHexFormatted(String hex, int bits) throws AssemblerException {
		var binary = hexToBinary(hex);
		var initialLength = binary.length();
		var zerosNeeded = bits - initialLength;
		var zeros = new StringBuilder();

		for (; zerosNeeded > 0; zerosNeeded -= 1) {
			zeros.append("0");
		}

		var finalString = zeros.append(binary).toString();

		return finalString;
	}

	public static String binaryFromIntFormatted(String intStr, int bits) throws AssemblerException {
		var binary = intToBinary(intStr);
		var initialLength = binary.length();
		var zerosNeeded = bits - initialLength;
		var zeros = new StringBuilder();

		for (; zerosNeeded > 0; zerosNeeded -= 1) {
			zeros.append("0");
		}

		var finalString = zeros.append(binary).toString();

		return finalString;
	}

	public static String binaryToHex(String binary) {
		Long l = Long.parseLong(binary, 2);
		return String.format("%X", l);
	}

	public static String hexToBinary(String s) {
		return new BigInteger(s, 16).toString(2);
	}

	public static String intToBinary(String intStr) {
		var i = Integer.parseInt(intStr);
		return Integer.toBinaryString(i);
	}

	public static boolean isAlpha(String s) {
		var pattern = "[a-zA-Z]*";

		if (s.matches(pattern)) {
			return true;
		}

		return false;
	}

	public static boolean isAlphaNumeric(String s) {
		var pattern = "[a-zA-Z0-9]*";

		if (s.matches(pattern)) {
			return true;
		}

		return false;
	}

	public static boolean isHexNumber(String str) {
		try {
			Long.parseLong(str, 16);
			return true;
		} catch (NumberFormatException e) {
			return false;
		}
	}

	public static boolean isNumeric(String s) {
		var pattern = "[0-9]*";

		if (s.matches(pattern)) {
			return true;
		}

		return false;
	}

	static public void writeLinesToFile(String filename, List<String> lines) {
		File file = null;

		try {
			file = new File(filename);
			file.createNewFile();
		} catch (Exception e) {
			e.printStackTrace();
		}

		try {
			var writer = new FileWriter(file);
			for (String line : lines) {
				writer.write(line + "\n");
			}
			writer.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private HashMap<String, String> assemblyTermTypeHash;
	private boolean atData, atText;
	private DataSource data;
	private boolean dataDeclared, textDeclared;
	private HashMap<String, Integer> dataTable;
	private HashMap<Integer, Integer> insAdrTable;
	private int insNumber;
	private List<List<String>> legitAssemblyOpTreePaths;
	private int locationCounter;
	@Getter
	private List<String> objectCode;
	private HashMap<String, Integer> symbolTable;

	/**
	 * <pre>
	 * Constructor for class, initialises variables and calls assemble() method.
	 * </pre>
	 *
	 * @param data - Data for assembler to work on.
	 * @throws AssemblerException
	 */
	public Assembler(DataSource data) throws AssemblerException {
		this.data = data;

		locationCounter = 0;
		insNumber = 0;
		insAdrTable = new HashMap<>();
		symbolTable = new HashMap<>();
		dataTable = new HashMap<>();

		legitAssemblyOpTreePaths = new ArrayList<>();
		assemblyTermTypeHash = new HashMap<>();

		atData = false;
		atText = false;
		dataDeclared = false;
		textDeclared = false;

		objectCode = new ArrayList<>();

		assemble();
	}

	private void analyseDataFirstPass(String assemblyLine) throws AssemblerException {
		var legitIntDataLine = Pattern.matches("[A-Za-z0-9]+\\s+[0-9]+MAU\\s+[^\\s]+", assemblyLine);
		var legitAsciiDataLine = Pattern.matches("[A-Za-z0-9]+\\s+.ascii\\s+\".+\"", assemblyLine);
		var legitUninitializedDataLine = Pattern.matches("[A-Za-z0-9]+\\s+[0-9]+MAU", assemblyLine);

		if (!legitIntDataLine && !legitAsciiDataLine && !legitUninitializedDataLine) {
			throw new AssemblerException(".data line incorrect syntax.");
		}

		var splitDataLine = assemblyLine.split("\\s+");
		var label = splitDataLine[0];
		var noOfMinAdrUnits = 0;

		if (legitAsciiDataLine) {
			var splitByQuotation = assemblyLine.split("\"", 2);
			var asciiData = splitByQuotation[1].substring(0, splitByQuotation[1].length() - 1);
			var noOfBits = 0;
			for (var i = 0; i < asciiData.length(); i++) {
				noOfBits += 8;
			}
			var minAdrUnit = data.getMinAdrUnit();
			noOfMinAdrUnits = noOfBits / minAdrUnit;
		}

		else if (legitIntDataLine || legitUninitializedDataLine) {
			var splitDataTerm = assemblyLine.split("\\s+");
			var minUnitTerm = splitDataTerm[1];
			var splitMinUnitTerm = minUnitTerm.split("MAU");
			var noOfMinAdrUnitsStr = splitMinUnitTerm[0];
			noOfMinAdrUnits = Integer.parseInt(noOfMinAdrUnitsStr);
		}

		if (symbolTable.get(label) == null && dataTable.get(label) == null) {
			dataTable.put(label, locationCounter);
		} else {
			throw new AssemblerException("\"" + label + "\" already exists in symbol table.");
		}

		insNumber++;
		insAdrTable.put(insNumber, locationCounter);
		locationCounter += noOfMinAdrUnits;
	}

	private void analyseInstructionsFirstPass(String assemblyLine) throws AssemblerException {
		legitAssemblyOpTreePaths = new ArrayList<>();
		analyseWithAssemblyOpTree(assemblyLine);

		log.debug("{}", legitAssemblyOpTreePaths);

		if (legitAssemblyOpTreePaths.isEmpty()) {
			throw new AssemblerException("Assembly line not consistent with assemblyOpTree. Please check tree.");
		}

		var mnemData = getMnemData(assemblyLine);

		if (mnemData == null) {
			throw new AssemblerException("Mnemonic not declared in MnemonicData section within specification file.");
		}

		var operandFormats = mnemData.getOperandsFormats();
		List<String> legitOpFormats = new ArrayList<>();

		// Find operand format matches
		for (String opFormat : operandFormats) {
			if (formatMatch(opFormat)) {
				legitOpFormats.add(opFormat);
			}
		}

		if (legitOpFormats.isEmpty()) {
			var error = new StringBuilder("Incorrectly formatted operands. Expected formats for mnemonic \"")
					.append(mnemData.getMnemonic()).append("\":\n");
			for (String opFormat : operandFormats) {
				error.append("\n").append(opFormat);
			}
			error.append("\n\nIt is assumed that the operands specified above are NOT optional.\n")
					.append("Operand tree built from assembly line:\n\n").append(legitAssemblyOpTreePaths);
			throw new AssemblerException(error.toString());
		}

		var relevantOperands = getRelevantOperands(legitOpFormats.get(0));
		String foundOpFormat = null;

		// Match syntax of line (separator commas match)
		for (String opFormat : legitOpFormats) {
			if (correctSyntax(opFormat, assemblyLine, relevantOperands)) {
				foundOpFormat = opFormat;
				break;
			}
		}

		if (foundOpFormat == null) {
			var error = new StringBuilder(
					"Assembly line syntax error. Check use of commas and spaces between operands. Expected syntax:\n");
			for (String opFormat : legitOpFormats) {
				error.append("\n").append(opFormat);
			}
			throw new AssemblerException(error.toString());
		}

		var format = mnemData.getOperandFormatHash().get(foundOpFormat);
		var instructionFormat = format.getInstructionFormat();
		var insSize = 0;

		for (String instruction : instructionFormat) {
			var insFormat = data.getInstructionFormatHash().get(instruction);
			List<String> instructions = insFormat.getFields();

			for (String field : instructions) {
				int bits = insFormat.getFieldBitHash().get(field);
				insSize += bits;
			}
		}

		var minAdrUnit = data.getMinAdrUnit();
		var noOfAdrUnits = insSize / minAdrUnit;
		insNumber++;
		insAdrTable.put(insNumber, locationCounter);

		// Find any relocation point labels
		var label = getLabelString();

		if (label != null) {
			if (symbolTable.get(label) == null && dataTable.get(label) == null) {
				symbolTable.put(label, locationCounter);
			} else {
				throw new AssemblerException("\"" + label + "\" already exists in symbol table.");
			}
		}

		locationCounter += noOfAdrUnits;
	}

	private void analyseLineFirstPass(String assemblyLine) throws AssemblerException {
		if (assemblyLine.equals(".data")) {
			if (dataDeclared) {
				throw new AssemblerException(".data section already declared.");
			}
			dataDeclared = true;
			atData = true;
			atText = false;
		} else if (assemblyLine.equals(".text")) {
			if (textDeclared) {
				throw new AssemblerException(".text section already declared.");
			}
			textDeclared = true;
			atData = false;
			atText = true;
		} else if (atData) {
			analyseDataFirstPass(assemblyLine);
		} else if (atText) {
			analyseInstructionsFirstPass(assemblyLine);
		} else {
			throw new AssemblerException("No section header (\".data\" or \".text\").");
		}

	}

	private void analyseLineSecondPass(String assemblyLine) throws AssemblerException {
		if (assemblyLine.equals(".data")) {
			atData = true;
			atText = false;
		} else if (assemblyLine.equals(".text")) {
			atData = false;
			atText = true;
		} else if (atData) {
			populateDataSecondPass(assemblyLine);
		} else if (atText) {
			populateInstructionSecondPass(assemblyLine);
		}
	}

	private boolean analyseOperands(List<String> tokens, List<String> assemblyTokens, List<String> tokensToAnalyse,
			List<String> fullExp, List<List<String>> paths, List<String> currentPath) {
		var done = false;

		log.debug("--------------------");
		log.debug("terms: {}", tokens);
		log.debug("paths: {}", paths);
		log.debug("curpath: {}", currentPath);
		log.debug("asslist: {}", assemblyTokens);
		log.debug("fulltermsIter: {}", fullExp);
		log.debug("termsIter: {}", tokensToAnalyse);

		for (String token : tokens) {
			log.debug(token);

			var furtherTokenSplit = token.split("\\s+");

			// If root expression
			if (furtherTokenSplit.length > 1) {
				List<String> furtherTokens = new ArrayList<>();
				Collections.addAll(furtherTokens, furtherTokenSplit);

				done = analyseOperands(furtherTokens, assemblyTokens, tokensToAnalyse, fullExp, paths, currentPath);

				if (done) {
					return true;
				} else {
					return false;
				}
			}

			// Single token
			else {

				var tempToken = "";

				if (token.charAt(token.length() - 1) == '?' || token.charAt(token.length() - 1) == '*'
						|| token.charAt(token.length() - 1) == '+') {
					tempToken = token.substring(0, token.length() - 1);
				} else {
					tempToken = token;
				}

				if (token.charAt(token.length() - 1) == '+') {

					List<String> oneOrMoreExp = new ArrayList<>();
					var oneOrMore = tempToken + " " + tempToken + "*";
					oneOrMoreExp.add(oneOrMore);
					var newTokensToAnalyse = updateExp(oneOrMoreExp, tokensToAnalyse, token);
					var newFullExp = updateExp(oneOrMoreExp, fullExp, token);

					done = analyseOperands(oneOrMoreExp, assemblyTokens, newTokensToAnalyse, newFullExp, paths,
							currentPath);

					if (done) {
						return true;
					} else {
						return false;
					}
				}

				else {
					var assemblyOpTreeToken = data.getAssemblyOpTree().getAssemblyOpTreeHash().get(tempToken);
					List<String> newCurrentPath = new ArrayList<>(currentPath);

					if (token.charAt(token.length() - 1) == '?') {
						newCurrentPath.add("?");
					}

					if (!token.startsWith("\"") || !token.endsWith("\"")) {
						newCurrentPath.add(tempToken);
					}

					// Not leaf expression
					if (assemblyOpTreeToken != null) {

						done = analyseOperands(assemblyOpTreeToken, assemblyTokens, tokensToAnalyse, fullExp, paths,
								newCurrentPath);

						if (done) {
							return true;
						}
					}

					// Leaf expression
					else {
						var assemblyTerm = assemblyTokens.get(0);

						if (match(tempToken, assemblyTerm)) {

							if (!newCurrentPath.contains(assemblyTerm)) {
								newCurrentPath.add(assemblyTerm);
							}

							log.debug("found: {}", token);

							if (!validWithTokensToAnalyse(tokensToAnalyse, newCurrentPath)) {
								return false;
							}

							List<List<String>> newPaths = new ArrayList<>(paths);
							newPaths.add(newCurrentPath);
							tokensToAnalyse = removeFirstToken(tokensToAnalyse, newCurrentPath);
							assemblyTokens = removeFirstToken(assemblyTokens);
							newCurrentPath = new ArrayList<>();

							if (tokensToAnalyse.isEmpty() || assemblyTokens.isEmpty()) {
								if (tokensToAnalyse.isEmpty() && !assemblyTokens.isEmpty()) {
									return false;
								} else if (!tokensToAnalyse.isEmpty() && assemblyTokens.isEmpty()
										&& !validWithFullExp(fullExp, newPaths)) {
									return false;
								}

								// Valid with tree
								legitAssemblyOpTreePaths = newPaths;
								return true;
							}

							done = analyseOperands(tokensToAnalyse, assemblyTokens, tokensToAnalyse, fullExp, newPaths,
									newCurrentPath);

							if (done) {
								return true;
							}
						}
					}
				}
			}
		}

		return done;
	}

	private void analyseWithAssemblyOpTree(String assemblyLine) throws AssemblerException {
		var assemblyOpTree = data.getAssemblyOpTree();
		var rootNode = assemblyOpTree.getRootToken();
		var roots = assemblyOpTree.getAssemblyOpTreeHash().get(rootNode);
		List<List<String>> paths = new ArrayList<>();
		List<String> currentPath = new ArrayList<>();
		List<String> assemblyTokens = new ArrayList<>();
		var assemblySplit = assemblyLine.split("\\s+"); // space

		for (String str : assemblySplit) {
			if (!str.matches(",+")) {
				str = str.replaceAll("^,+", "");
				str = str.replaceAll(",+$", "");
				assemblyTokens.add(str);
			}
		}

		for (String rootTokens : roots) {
			List<String> rootTerm = new ArrayList<>();
			rootTerm.add(rootTokens);

			try {
				if (analyseOperands(rootTerm, assemblyTokens, rootTerm, rootTerm, paths, currentPath)) {
					break;
				}
			} catch (StackOverflowError e) {
				throw new AssemblerException("StackOverflow: Check tree has no infinite loops.");
			}
		}
	}

	private void assemble() throws AssemblerException {
		firstPass();

		// to account for last line
		insNumber++;
		insAdrTable.put(insNumber, locationCounter);

		insNumber = 0;
		secondPass();
	}

	private boolean correctSyntax(String format, String assemblyLine, List<String> relevantOperands) {
		var formatSplit = format.split("\\s+");
		var noOfTokens = formatSplit.length;

		var regex = new StringBuilder(".*");

		var i = 1;
		var i2 = 0;

		for (String str : formatSplit) {

			if (i > 1 && i <= noOfTokens) {
				regex.append("\\s+");
			}

			var strSplit = str.split("((?=^[,]*)|(?<=^[,]*))|((?=[,]*$)|(?<=[,]*$))");

			for (String str2 : strSplit) {
				if (!str2.isEmpty()) {
					if (str2.equals(",")) {
						regex.append(",");
					} else {
						regex.append("(").append(Pattern.quote(relevantOperands.get(i2))).append(")");
						i2++;
					}
				}
			}
			i++;
		}

		var legitSyntax = Pattern.matches(regex.toString(), assemblyLine);

		return legitSyntax;
	}

	private String dataOffset(String assemblyTerm, int bits) {
		int dataOffset = dataTable.get(assemblyTerm);
		var binary = Integer.toBinaryString(dataOffset);

		if (binary.length() > bits) {
			binary = binary.substring(binary.length() - bits);
		}

		return binary;
	}

	private void firstPass() throws AssemblerException {
		var lineCounter = 0;

		for (String assemblyLine : data.getAssemblyCode()) {
			lineCounter++;
			var commentSplit = assemblyLine.split(";");
			try {
				assemblyLine = commentSplit[0];
			} catch (ArrayIndexOutOfBoundsException e) {
				assemblyLine = "";
			}

			assemblyLine = assemblyLine.trim();

			if (assemblyLine.length() > 0) {
				try {
					analyseLineFirstPass(assemblyLine);
				} catch (AssemblerException e) {
					var error = getErrorMessage(lineCounter, assemblyLine, e.getMessage());
					objectCode.add(error);
					writeLinesToFile("object_code.txt", objectCode);
					throw e;
				}
			}
		}
	}

	private boolean formatMatch(String mnemFormat) {
		var mnemFormatSplit = mnemFormat.split("\\s+");
		List<String> mnemFormatTokens = new ArrayList<>();

		for (String token : mnemFormatSplit) {
			token = token.replaceAll("^,+", "");
			token = token.replaceAll(",+$", "");
			if (!token.isEmpty()) {
				mnemFormatTokens.add(token);
			}
		}

		var i = 0;
		var found = false;
		var optional = false;

		for (List<String> path : legitAssemblyOpTreePaths) {

			for (String pathTerm : path) {

				if (i >= mnemFormatTokens.size()) {
					return false;
				}

				if (pathTerm.equals(mnemFormatTokens.get(i))) {
					found = true;
				} else if (pathTerm.equals("?")) {
					optional = true;
				}
			}

			// Assumes nodes specified in operand format are not optional
			if (found && !optional) {
				i++;
			} else if (!found && !optional) {
				return false;
			}

			found = false;
			optional = false;
		}

		if (i != mnemFormatTokens.size()) {
			return false;
		}

		return true;
	}

	private String getAssemblyOperand(List<String> path) {
		var operand = path.get(path.size() - 1);
		return operand.replaceAll("\"", "");
	}

	private String getErrorMessage(int lineCounter, String assemblyLine, String message) {
		var msg = new StringBuilder("------------------------------------------\n");
		msg.append("Exception at line ").append(lineCounter).append(" :\n");
		msg.append("\n");
		msg.append(assemblyLine).append("\n");
		msg.append("------------------------------------------\n");
		msg.append("\n");
		msg.append(message).append("\n\n");

		return msg.toString();
	}

	private String getHexObjCode(List<String> binaryArray) {
		var hexObjCode = new StringBuilder();
		var minAdrUnit = data.getMinAdrUnit();
		var noOfHexCharacters = minAdrUnit / 8 * 2;

		if (data.getEndian().equals("big")) {
			for (String str : binaryArray) {
				var hex = binaryToHex(str);
				while (hex.length() < noOfHexCharacters) {
					hex = "0" + hex;
				}
				hexObjCode.append(hex).append(" ");
			}
		}

		else if (data.getEndian().equals("little")) {
			var counter = binaryArray.size() - 1;
			for (; counter >= 0; counter--) {
				var hex = binaryToHex(binaryArray.get(counter));
				while (hex.length() < noOfHexCharacters) {
					hex = "0" + hex;
				}
				hexObjCode.append(hex).append(" ");
			}
		}

		return hexObjCode.toString();
	}

	private String getLabelString() {
		// Assumes relocation labels at beginning of instruction (in first path)
		String label = null;
		var foundLabel = false;

		for (List<String> path : legitAssemblyOpTreePaths) {
			for (String term : path) {

				if (term.equals("LABEL")) {
					foundLabel = true;
				}

				if (foundLabel) {
					label = term;
				}
			}
			break;
		}

		return label;
	}

	private Mnemonic getMnemData(String assemblyLine) throws AssemblerException {
		var assemblyLineSplit = assemblyLine.split("\\s+");
		List<String> assemblyTermList = new ArrayList<>();

		for (String assemblyTerm : assemblyLineSplit) {
			assemblyTerm = assemblyTerm.replaceAll("^,+", "");
			assemblyTerm = assemblyTerm.replaceAll(",+$", "");
			assemblyTermList.add(assemblyTerm);
		}

		Mnemonic mnemData = null;

		for (String assemblyTerm : assemblyTermList) {
			if (data.getMnemonicTable().get(assemblyTerm) != null) {
				mnemData = data.getMnemonicTable().get(assemblyTerm);
				break;
			}
		}

		return mnemData;
	}

	private List<String> getRelevantOperands(String format) {
		List<String> relevantOps = new ArrayList<>();
		var mnemFormatSplit = format.split("\\s+");
		List<String> mnemFormatTokens = new ArrayList<>();

		for (String formatTerm : mnemFormatSplit) {
			formatTerm = formatTerm.replaceAll("^,+", "");
			formatTerm = formatTerm.replaceAll(",+$", "");
			if (!formatTerm.isEmpty()) {
				mnemFormatTokens.add(formatTerm);
			}
		}

		var i = 0;
		var found = false;
		var optional = false;

		for (List<String> path : legitAssemblyOpTreePaths) {
			for (String pathTerm : path) {

				if (pathTerm.equals(mnemFormatTokens.get(i))) {
					found = true;
				} else if (pathTerm.equals("?")) {
					optional = true;
				}
			}

			// Assumes nodes in operand format are not optional
			if (found && !optional) {
				i++;
				relevantOps.add(getAssemblyOperand(path));
			}

			found = false;
			optional = false;
		}

		return relevantOps;
	}

	private boolean legitPath(List<String> path, String iterTerm) {
		for (String pathTerm : path) {
			if (iterTerm.equals(pathTerm)) {
				return true;
			}
		}

		return false;
	}

	private HashMap<String, String> mapInsFieldLabels(List<String> relevantOperands, String fieldEncodingLine)
			throws AssemblerException {
		var insHash = new HashMap<String, String>();
		var opFieldEncodings = fieldEncodingLine.split("\\s+");

		if (relevantOperands.size() != opFieldEncodings.length) {
			var error = new StringBuilder("Token mismatch between source assembly operands and operand fields:\n\n");
			error.append("Source assembly operands: ");
			for (String operand : relevantOperands) {
				error.append(operand).append(" ");
			}
			error.append("\nOperand field encodings:  ").append(fieldEncodingLine);
			error.append("\n\nField encodings should be mapped to the corresponding operand delimited by whitespace. ")
					.append("\nExample input:\n\n").append("mnem reg32, reg32").append("\n\tmnem rm reg");
			throw new AssemblerException(error.toString());
		}

		var i1 = 0;

		for (String op : opFieldEncodings) {
			var assemblyToken = relevantOperands.get(i1);
			var splitFieldTokens = op.split("(?=[^a-zA-Z0-9])|(?<=[^a-zA-Z0-9])");
			var prefixes = "";

			for (String str : splitFieldTokens) {
				if (!isAlphaNumeric(str)) {
					prefixes += "\\" + str;
				}
			}

			String[] splitAssemblyTokens;

			if (prefixes.isEmpty()) {
				splitAssemblyTokens = new String[1];
				splitAssemblyTokens[0] = assemblyToken;
			} else {
				splitAssemblyTokens = assemblyToken.split("(?=[" + prefixes + "])|(?<=[" + prefixes + "])");
			}

			if (splitAssemblyTokens.length != splitFieldTokens.length) {
				var error = new StringBuilder("Syntax mismatch between instruction operands and field encodings:\n\n");
				error.append("Source assembly operands:  ");
				for (String operand : relevantOperands) {
					error.append(operand).append(" ");
				}
				error.append("\nOperand field encodings:  ").append(fieldEncodingLine);
				error.append("\n\nSeparator commas should NOT be specified within the operand field encoding tokens, ")
						.append("\nExample input:\n\n").append("mnem reg32, reg32").append("\n\tmnem rm reg");

				throw new AssemblerException(error.toString());
			}

			var i2 = 0;

			for (String insTerm : splitFieldTokens) {
				if (!isAlphaNumeric(insTerm)) {
					if (!insTerm.equals(splitAssemblyTokens[i2])) {
						var error = "Could not map instruction fields to assembly line:\n\n" + fieldEncodingLine;
						throw new AssemblerException(error);
					}
				} else {
					var assemblyTerm = splitAssemblyTokens[i2];
					insHash.put(insTerm, assemblyTerm);
				}
				i2++;
			}
			i1++;
		}

		return insHash;
	}

	private boolean match(String assemblyOpTreeTerm, String assemblyTerm) {
		if (assemblyOpTreeTerm.startsWith("\"") && assemblyOpTreeTerm.endsWith("\"")) {
			assemblyOpTreeTerm = assemblyOpTreeTerm.replaceAll("\"", "");

			return assemblyOpTreeTerm.equals(assemblyTerm);
		} else {
			return nestedMatch(assemblyOpTreeTerm, assemblyTerm);
		}
	}

	private boolean nestedMatch(String assemblyOpTreeTerm, String assemblyTerm) {
		var splitAssemblyOpTreeTerms = assemblyOpTreeTerm.split("(?=[^a-zA-Z0-9])|(?<=[^a-zA-Z0-9])");
		var prefixes = "";

		for (String str : splitAssemblyOpTreeTerms) {
			if (!isAlphaNumeric(str)) {
				prefixes += "\\" + str;
			}
		}

		String[] splitAssemblyTerms;

		if (prefixes.isEmpty()) {
			splitAssemblyTerms = new String[1];
			splitAssemblyTerms[0] = assemblyTerm;
		} else {
			splitAssemblyTerms = assemblyTerm.split("(?=[" + prefixes + "])|(?<=[" + prefixes + "])");
		}

		if (splitAssemblyOpTreeTerms.length != splitAssemblyTerms.length) {
			return false;
		}

		var i = 0;

		for (String term : splitAssemblyOpTreeTerms) {

			if (term.isEmpty() || splitAssemblyTerms[i].isEmpty()) {
				if (!term.isEmpty() || !splitAssemblyTerms[i].isEmpty()) {
					return false;
				}
			}
			// Symbol
			else if (!isAlphaNumeric(term)) {
				if (!term.equals(splitAssemblyTerms[i])) {
					return false;
				}
			}
			// AlphaNumeric
			else if (!term.equals(splitAssemblyTerms[i])) {
				var assemblyOpTreeTerms = data.getAssemblyOpTree().getAssemblyOpTreeHash().get(term);

				// Node
				if (assemblyOpTreeTerms != null) {

					var legit = false;

					for (String termFromHash : assemblyOpTreeTerms) {
						if (match(termFromHash, splitAssemblyTerms[i])) {
							legit = true;
							break;
						}
					}

					if (!legit) {
						return false;
					}
				}

				// Is register or mnemonic
				else if (data.getRegisterHash().get(splitAssemblyTerms[i]) != null
						|| data.getMnemonicTable().get(splitAssemblyTerms[i]) != null) {
					return false;
				} else if (term.equals("HEX")) {
					if (!isHexNumber(splitAssemblyTerms[i])) {
						return false;
					}
					assemblyTermTypeHash.put(splitAssemblyTerms[i], term);
				}

				else if (term.equals("INT")) {
					if (!isNumeric(splitAssemblyTerms[i])) {
						return false;
					}
					assemblyTermTypeHash.put(splitAssemblyTerms[i], term);
				}

				else if (term.equals("LABEL")) {
					if (!isAlpha(splitAssemblyTerms[i])) {
						return false;
					}
					assemblyTermTypeHash.put(splitAssemblyTerms[i], term);
				} else {
					return false;
				}
			}

			i++;
		}

		return true;
	}

	private void populateDataSecondPass(String assemblyLine) throws AssemblerException {
		insNumber++;

		var legitIntDataLine = Pattern.matches("[A-Za-z0-9]+\\s+[0-9]+MAU\\s+[^\\s]+", assemblyLine);
		var legitAsciiDataLine = Pattern.matches("[A-Za-z0-9]+\\s+.ascii\\s+\".+\"", assemblyLine);
		var legitUninitializedDataLine = Pattern.matches("[A-Za-z0-9]+\\s+[0-9]+MAU", assemblyLine);
		var binary = "";
		List<String> binaryArray = null;

		if (legitAsciiDataLine) {
			var splitByQuotation = assemblyLine.split("\"", 2);
			var asciiData = splitByQuotation[1].substring(0, splitByQuotation[1].length() - 1);
			binary = "";

			for (var i = 0; i < asciiData.length(); i++) {
				var character = asciiData.charAt(i);
				var ascii = character;
				var asciiBinary = Integer.toBinaryString(ascii);
				binary += binaryFormatted(asciiBinary, 8);
			}

			binaryArray = splitToMinAdrUnits(binary);
		} else if (legitIntDataLine) {
			var splitDataLine = assemblyLine.split("\\s+");
			var integer = splitDataLine[2];

			try {
				binary = intToBinary(integer);
			} catch (NumberFormatException e) {
				throw new AssemblerException("\"" + integer + "\" is not a valid integer.");
			}

			var minUnitTerm = splitDataLine[1];
			var splitMinUnitTerm = minUnitTerm.split("MAU");
			var noOfMinAdrUnitsStr = splitMinUnitTerm[0];
			var noOfMinAdrUnits = Integer.parseInt(noOfMinAdrUnitsStr);
			var minAdrUnit = data.getMinAdrUnit();
			var noOfBits = noOfMinAdrUnits * minAdrUnit;
			binary = binaryFormatted(binary, noOfBits);
			binaryArray = splitToMinAdrUnits(binary);

			if (binaryArray.size() > noOfMinAdrUnits) {
				throw new AssemblerException("\"" + integer + "\" exceeds expected bits.");
			}
		} else if (legitUninitializedDataLine) {
			var splitDataLine = assemblyLine.split("\\s+");
			var minUnitTerm = splitDataLine[1];
			var splitMinUnitTerm = minUnitTerm.split("MAU");
			var noOfMinAdrUnitsStr = splitMinUnitTerm[0];
			var noOfMinAdrUnits = Integer.parseInt(noOfMinAdrUnitsStr);
			var minAdrUnit = data.getMinAdrUnit();
			var numberOfzeros = minAdrUnit * noOfMinAdrUnits;
			binary = binaryFormatted(binary, numberOfzeros);
			binaryArray = splitToMinAdrUnits(binary);
		}

		int adr = insAdrTable.get(insNumber);
		var address = Integer.toHexString(adr) + ":";
		var hexObjCode = getHexObjCode(binaryArray);
		var objectCodeLine = String.format("%-10s %s", address, hexObjCode);
		objectCode.add(objectCodeLine);

		log.debug(objectCodeLine);
	}

	private void populateInstructionSecondPass(String assemblyLine) throws AssemblerException {
		log.debug("*****************************");
		log.debug(assemblyLine);

		legitAssemblyOpTreePaths = new ArrayList<>();
		assemblyTermTypeHash = new HashMap<>();
		analyseWithAssemblyOpTree(assemblyLine);

		log.debug("{}", legitAssemblyOpTreePaths);

		var mnemData = getMnemData(assemblyLine);
		var operandFormats = mnemData.getOperandsFormats();
		List<String> legitOpFormats = new ArrayList<>();

		// Find operand format matches
		for (String opFormat : operandFormats) {
			if (formatMatch(opFormat)) {
				legitOpFormats.add(opFormat);
			}
		}

		var relevantOperands = getRelevantOperands(legitOpFormats.get(0));
		String foundOpFormat = null;

		// Match syntax of line (separator commas match)
		for (String opFormat : legitOpFormats) {
			if (correctSyntax(opFormat, assemblyLine, relevantOperands)) {
				foundOpFormat = opFormat;
				break;
			}
		}

		var format = mnemData.getOperandFormatHash().get(foundOpFormat);
		var opFieldEncodings = format.getOperandFieldEncodings();
		HashMap<String, String> insFieldHash = null;

		if (opFieldEncodings != "") {
			insFieldHash = mapInsFieldLabels(relevantOperands, opFieldEncodings);
		}

		var instructionFormat = format.getInstructionFormat();
		var binary = new StringBuilder();
		insNumber++;

		log.debug("opFieldHash: " + insFieldHash);
		log.debug("assTypeHash: " + assemblyTermTypeHash);

		for (String instruction : instructionFormat) {
			var insFormat = data.getInstructionFormatHash().get(instruction);
			List<String> instructions = insFormat.getFields();

			for (String field : instructions) {
				var binaryTemp = "";

				int bits = insFormat.getFieldBitHash().get(field);

				if (mnemData.getGlobalFieldEncodingHash().get(field) != null) {
					binaryTemp = mnemData.getGlobalFieldEncodingHash().get(field);
				} else if (format.getFieldBitHash().get(field) != null) {
					binaryTemp = format.getFieldBitHash().get(field);
				} else if (insFieldHash.get(field) != null) {

					var assemblyTerm = insFieldHash.get(field);

					if (data.getRegisterHash().get(assemblyTerm) != null) {
						binaryTemp = data.getRegisterHash().get(assemblyTerm);
					} else if (assemblyTermTypeHash.get(assemblyTerm) != null) {
						var type = assemblyTermTypeHash.get(assemblyTerm);

						if (type.equals("INT")) {
							binaryTemp = intToBinary(assemblyTerm);
						} else if (type.equals("HEX")) {
							binaryTemp = hexToBinary(assemblyTerm);
						} else if (type.equals("LABEL")) {

							if (symbolTable.get(assemblyTerm) != null) {
								binaryTemp = relativeJumpInBinary(assemblyTerm, bits);
							} else if (dataTable.get(assemblyTerm) != null) {
								binaryTemp = dataOffset(assemblyTerm, bits);
							} else {
								throw new AssemblerException("Label \"" + assemblyTerm + " \" not found.");
							}
						}
					} else {
						throw new AssemblerException("Encoding data for \"" + assemblyTerm
								+ "\" (for instrucution field \"" + field
								+ "\") not found.\nIf term is a register, make sure it is defined as \"" + assemblyTerm
								+ "\" in registers (i.e., " + assemblyTerm
								+ " 001B).\nIf term is an INT etc, make sure it is specified as so in assemblyOpTree (i.e., immediate : INT).");
					}

					var binaryLength = binaryTemp.length();

					if (binaryLength > bits) {

						var error = "Bit representation of \"" + assemblyTerm + "\" exceeds expected number of bits ("
								+ bits + ")\nfor instruction field \"" + field + "\".";
						throw new AssemblerException(error);

					}

				}

				binary.append(binaryFormatted(binaryTemp, bits));
			}
		}

		var binaryArray = splitToMinAdrUnits(binary.toString());
		int adr = insAdrTable.get(insNumber);
		var address = Integer.toHexString(adr) + ":";
		var hexObjCode = getHexObjCode(binaryArray);
		var objectCodeLine = String.format("%-10s %s", address, hexObjCode);
		objectCode.add(objectCodeLine);

		log.debug(objectCodeLine);
	}

	private String relativeJumpInBinary(String insHashTerm, int bits) {
		int locationCounter = insAdrTable.get(insNumber + 1);
		int destination = symbolTable.get(insHashTerm);
		var jump = destination - locationCounter;
		var binary = Integer.toBinaryString(jump);

		if (binary.length() > bits) {
			binary = binary.substring(binary.length() - bits);
		}

		return binary;
	}

	private List<String> removeFirstToken(List<String> list) {
		var first = true;
		List<String> newList = new ArrayList<>();

		for (String str : list) {
			if (first) {
				first = false;
			} else {
				newList.add(str);
			}
		}

		return newList;
	}

	private List<String> removeFirstToken(List<String> tokensToAnalyseArray, List<String> currentPath) {
		List<String> newTermsIter = new ArrayList<>();
		var newTokensToAnalyse = "";
		var tokensToAnalyse = tokensToAnalyseArray.get(0);
		var splitTokensToAnalyse = tokensToAnalyse.split("\\s+");
		var found = false;
		var index = 0;

		for (String token : splitTokensToAnalyse) {
			for (String pathTerm : currentPath) {
				var tempToken = "";

				if (token.charAt(token.length() - 1) == '*' || token.charAt(token.length() - 1) == '?') {
					tempToken = token.substring(0, token.length() - 1);
				} else {
					tempToken = token;
				}

				if (tempToken.equals(pathTerm)) {
					found = true;
					break;
				}
			}

			if (found && token.charAt(token.length() - 1) == '*') {
				return tokensToAnalyseArray;
			}

			if (found) {
				index++;
				break;
			}
			index++;
		}

		for (String token : splitTokensToAnalyse) {
			if (index <= 0) {
				newTokensToAnalyse += token + " ";
			}
			index--;
		}

		newTokensToAnalyse = newTokensToAnalyse.trim();

		if (newTokensToAnalyse != "") {
			newTermsIter.add(newTokensToAnalyse);
		}

		return newTermsIter;
	}

	private void secondPass() throws AssemblerException {
		var lineCounter = 0;

		for (String assemblyLine : data.getAssemblyCode()) {
			lineCounter++;
			var commentSplit = assemblyLine.split(";");

			try {
				assemblyLine = commentSplit[0];
			} catch (ArrayIndexOutOfBoundsException e) {
				assemblyLine = "";
			}

			assemblyLine = assemblyLine.trim();

			if (assemblyLine.length() > 0) {
				try {
					analyseLineSecondPass(assemblyLine);
				} catch (AssemblerException e) {
					var error = getErrorMessage(lineCounter, assemblyLine, e.getMessage());
					objectCode.add(error);
					writeLinesToFile("object_code.txt", objectCode);
					throw e;
				}
			}
		}
	}

	private List<String> splitToMinAdrUnits(String binary) {
		List<String> binaryArray = new ArrayList<>();
		var minAdrUnit = data.getMinAdrUnit();
		var index = 0;

		while (index < binary.length()) {
			binaryArray.add(binary.substring(index, Math.min(index + minAdrUnit, binary.length())));
			index += minAdrUnit;
		}

		return binaryArray;
	}

	private List<String> updateExp(List<String> updateExp, List<String> expToUpdate, String tokenToChange) {
		List<String> newTermsIter = new ArrayList<>();
		var newExpStr = "";
		var exp = expToUpdate.get(0);
		var splitExp = exp.split("\\s+");
		var done = false;

		for (String token : splitExp) {
			if (token.equals(tokenToChange) && !done) {
				for (String str : updateExp) {
					newExpStr += str + " ";
					done = true;
				}
			} else {
				newExpStr += token + " ";
			}
		}

		newExpStr = newExpStr.trim();
		newTermsIter.add(newExpStr);

		return newTermsIter;
	}

	private boolean validWithFullExp(List<String> fullExp, List<List<String>> newPaths) {
		var exp = fullExp.get(0);
		var splitExp = exp.split("\\s+");
		var pathsFinished = false;
		var i = 0;
		List<String> path = null;

		for (String token : splitExp) {

			if (pathsFinished) {
				if (token.charAt(token.length() - 1) != '?' && token.charAt(token.length() - 1) != '*') {
					return false;
				}
			}

			else {
				path = newPaths.get(i);
				var tempToken = "";

				if (token.charAt(token.length() - 1) == '?' || token.charAt(token.length() - 1) == '*'
						|| token.charAt(token.length() - 1) == '+') {
					tempToken = token.substring(0, token.length() - 1);
				} else {
					tempToken = token;
				}

				if (token.charAt(token.length() - 1) == '*') {

					while (legitPath(path, tempToken)) {
						i++;
						if (i > newPaths.size() - 1) {
							pathsFinished = true;
							break;
						} else {
							path = newPaths.get(i);
						}
					}
				}

				else if (!legitPath(path, tempToken)) {
					if (token.charAt(token.length() - 1) != '?' && token.charAt(token.length() - 1) != '*') {
						return false;
					}
				}

				else {
					i++;
					if (i > newPaths.size() - 1) {
						pathsFinished = true;
					}
				}
			}
		}

		return true;
	}

	private boolean validWithTokensToAnalyse(List<String> tokensToAnalyseArray, List<String> currentPath) {
		var legit = false;
		var tokensToAnalyse = tokensToAnalyseArray.get(0);
		var splitTokensToAnalyse = tokensToAnalyse.split("\\s+");

		for (String token : splitTokensToAnalyse) {
			var tempToken = "";

			if (token.charAt(token.length() - 1) == '?' || token.charAt(token.length() - 1) == '*'
					|| token.charAt(token.length() - 1) == '+') {
				tempToken = token.substring(0, token.length() - 1);
			} else {
				tempToken = token;
			}

			for (String pathTerm : currentPath) {
				if (tempToken.equals(pathTerm) || token.equals(pathTerm)) {
					legit = true;
					break;
				}
			}

			if (legit) {
				return true;
			} else if (token.charAt(token.length() - 1) != '?' && token.charAt(token.length() - 1) != '*') {
				return false;
			}
		}

		return false;
	}
}
