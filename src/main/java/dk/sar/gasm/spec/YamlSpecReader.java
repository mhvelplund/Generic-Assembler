package dk.sar.gasm.spec;

import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.stream.Collectors;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import dk.sar.gasm.FileParserException;
import dk.sar.gasm.data.SpecFile;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

// @Slf4j
@RequiredArgsConstructor
public class YamlSpecReader implements SpecReader {
	@NonNull
	private final String fileName;

	@Override
	public SpecFile getSpecFile() throws IOException, FileParserException {
		try {
			var mapper = new ObjectMapper(new YAMLFactory());
			return mapper.readValue(new File(fileName), SpecFile.class);
		} catch (JsonProcessingException e) {
			throw new FileParserException(e.getMessage(), Arrays.stream(e.getStackTrace()).map(l -> l.toString()).collect(Collectors.toList()));
		}
	}

}
