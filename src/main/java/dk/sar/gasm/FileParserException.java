package dk.sar.gasm;

import java.util.List;

import lombok.Data;
import lombok.EqualsAndHashCode;

@Data
@SuppressWarnings("serial")
@EqualsAndHashCode(callSuper = false)
public class FileParserException extends Exception {
	private final List<String> errorReport;

	public FileParserException(String message, List<String> errorReport) {
		super(message);
		this.errorReport = errorReport;
	}
}
