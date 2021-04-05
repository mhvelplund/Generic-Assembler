package dk.sar.gasm.data;

import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import lombok.Data;

@Data
public class AssemblyOpTree {
	private Map<String, List<String>> assemblyOpTreeHash = new HashMap<>();
	private Set<String> assemblyOpTreeTokens = new HashSet<>();
	private String rootToken;
}
