package dk.sar.gasm;

/**
 * Eddie Graham
 * 1101301g
 * Individual Project 4
 * Supervisor: John T O'Donnell
 */

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;

@Data
public class Mnemonic {
	private Map<String, String> globalFieldEncodingHash = new HashMap<>();
	private String mnemonic = "";
	private Map<String, OperandFormat> operandFormatHash = new HashMap<>();
	private List<String> operandsFormats = new ArrayList<>();
	@JsonIgnore	private String rawGlobalFieldEncodingString = "";
	@JsonIgnore	private List<String> rawLines = new ArrayList<>();
	@JsonIgnore	private String rawLinesString = "";

	public void addToRawLines(String str) {
		this.rawLines.add(str);
		this.rawLinesString += str + "\n";
	}
}
