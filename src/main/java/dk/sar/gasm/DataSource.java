package dk.sar.gasm;

/**
 * Eddie Graham
 * 1101301g
 * Individual Project 4
 * Supervisor: John T O'Donnell
 */

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;

@Data
public class DataSource {
	private String architecture;
	@JsonIgnore private ArrayList<String> assemblyCode = new ArrayList<>();
	private AssemblyOpTree assemblyOpTree = new AssemblyOpTree();
	private String endian;
	private Map<String, InstructionFormat> instructionFormatHash = new HashMap<>();
	private int minAdrUnit;
	private Map<String, Mnemonic> mnemonicTable = new HashMap<>();
	private Map<String, String> registerHash = new HashMap<>();
}
