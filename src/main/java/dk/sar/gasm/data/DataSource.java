package dk.sar.gasm.data;

/**
 * Eddie Graham
 * 1101301g
 * Individual Project 4
 * Supervisor: John T O'Donnell
 */

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import lombok.Data;

/**
 * @deprecated Assembly code and spec description should be split into separate files.
 */
@Data
@Deprecated
public class DataSource {
	private List<String> assemblyCode = new ArrayList<>();
	private SpecFile spec = new SpecFile();

	public String getArchitecture() {
		return spec.getArchitecture();
	}

	public AssemblyOpTree getAssemblyOpTree() {
		return spec.getAssemblyOpTree();
	}

	public String getEndian() {
		return spec.getEndian();
	}

	public Map<String, InstructionFormat> getInstructionFormatHash() {
		return spec.getInstructionFormatHash();
	}

	public int getMinAdrUnit() {
		return spec.getMinAdrUnit();
	}

	public Map<String, Mnemonic> getMnemonicTable() {
		return spec.getMnemonicTable();
	}

	public Map<String, String> getRegisterHash() {
		return spec.getRegisterHash();
	}

	public void setArchitecture(String architecture) {
		spec.setArchitecture(architecture);
	}

	public void setAssemblyOpTree(AssemblyOpTree assemblyOpTree) {
		spec.setAssemblyOpTree(assemblyOpTree);
	}

	public void setEndian(String endian) {
		spec.setEndian(endian);
	}

	public void setInstructionFormatHash(Map<String, InstructionFormat> instructionFormatHash) {
		spec.setInstructionFormatHash(instructionFormatHash);
	}

	public void setMinAdrUnit(int minAdrUnit) {
		spec.setMinAdrUnit(minAdrUnit);
	}

	public void setMnemonicTable(Map<String, Mnemonic> mnemonicTable) {
		spec.setMnemonicTable(mnemonicTable);
	}

	public void setRegisterHash(Map<String, String> registerHash) {
		spec.setRegisterHash(registerHash);
	}
}
