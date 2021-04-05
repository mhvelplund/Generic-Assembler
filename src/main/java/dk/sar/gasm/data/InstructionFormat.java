package dk.sar.gasm.data;

/**
 * Eddie Graham
 * 1101301g
 * Individual Project 4
 * Supervisor: John T O'Donnell
 */

import java.util.ArrayList;
import java.util.HashMap;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;

@Data
public class InstructionFormat {
	private HashMap<String, Integer> fieldBitHash = new HashMap<>();
	private ArrayList<String> fields = new ArrayList<>();
	private String instructionName;
	@JsonIgnore private String rawLineString;
}
