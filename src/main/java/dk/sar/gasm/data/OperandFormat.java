package dk.sar.gasm.data;

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
public class OperandFormat {
	private Map<String, String> fieldBitHash = new HashMap<>();
	private List<String> instructionFormat = new ArrayList<>();
	private String mnemFormat = "";
	private String operandFieldEncodings = "";
	@JsonIgnore	private String rawLinesString = "";

	public void addToRawLineString(String str) {
		rawLinesString += str + "\n";
	}
}
