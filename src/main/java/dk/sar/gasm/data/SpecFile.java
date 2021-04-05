package dk.sar.gasm.data;

import java.util.HashMap;
import java.util.Map;

import lombok.Data;

@Data
public class SpecFile {
	private String architecture;
	private AssemblyOpTree assemblyOpTree = new AssemblyOpTree();
	private String endian;
	private Map<String, InstructionFormat> instructionFormatHash = new HashMap<>();
	private int minAdrUnit;
	private Map<String, Mnemonic> mnemonicTable = new HashMap<>();
	private Map<String, String> registerHash = new HashMap<>();
}