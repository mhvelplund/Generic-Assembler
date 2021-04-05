package dk.sar.gasm.spec;

import java.io.IOException;

import dk.sar.gasm.FileParserException;
import dk.sar.gasm.data.SpecFile;

/** Load a specification and parse it into a {@link SpecFile}. */
public interface SpecReader {
	SpecFile getSpecFile() throws IOException, FileParserException;
}
