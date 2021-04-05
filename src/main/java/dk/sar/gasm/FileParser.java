package dk.sar.gasm;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

import dk.sar.gasm.data.DataSource;
import dk.sar.gasm.spec.SpecReader;
import dk.sar.gasm.spec.YamlSpecReader;
import lombok.Getter;

/**
 * This class parses both the specification and assembly files and stores the
 * information in the data source (DataSource.java).
 *
 * @author Eddie Graham
 */
@SuppressWarnings("deprecation")
public class FileParser {
	@Getter
	private DataSource data;

	/**
	 * Constructor for class, initializes variables and calls methods which scan
	 * both files
	 *
	 * @param specFile
	 * @param assemblyFile
	 * @throws IOException
	 * @throws FileParserException
	 */
	public FileParser(String specFile, String assemblyFile) throws IOException, FileParserException {
		this.data = new DataSource();

		var lines = Files.readAllLines(Paths.get(new File(assemblyFile).getCanonicalPath()));
		data.setAssemblyCode(lines);

//		SpecReader reader = new LegacySpecReader(specFile);
		SpecReader reader = new YamlSpecReader(specFile);
		data.setSpec(reader.getSpecFile());
	}
}
