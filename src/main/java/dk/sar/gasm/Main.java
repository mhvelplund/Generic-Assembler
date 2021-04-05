package dk.sar.gasm;

import java.io.IOException;

import com.google.common.collect.Lists;

import lombok.extern.slf4j.Slf4j;

/**
 * Eddie Graham 1101301g Individual Project 4 Supervisor: John T O'Donnell
 */

/*
 * The Generic-Assembler reads in two inputs: (1) a specification of the
 * computer architecture and assembly language, and (2) a source program written
 * in that assembly language. The software then outputs the corresponding
 * machine language result.
 */
@Slf4j
public class Main {

	/**
	 * Usage: args[0] is specification file name args[1] is assembly file name
	 */
	public static void main(String[] args) {

		if (args.length == 0) {
			log.error("Specification and assembly filenames not given.");
			System.exit(1);
		}

		else if (args.length == 1) {
			log.error("Assembly file not given.");
			log.error("Specification file: " + args[0]);
			System.exit(1);
		}

		else if (args.length > 2) {
			log.error("Too many arguments provided.");
			System.exit(1);
		}

		if (!args[0].endsWith(".txt") || !args[1].endsWith(".txt")) {
			log.error("Input is limited to two .txt files.");
			System.exit(1);
		}

		try {
			var file = new FileParser(args[0], args[1]);
			var data = file.getData();

//		try {
//			var mapper = new ObjectMapper(new YAMLFactory());
//			var json = mapper.writeValueAsString(data);
//			System.out.println(json);
//			// User user = mapper.readValue(yamlSource, User.class);
//		} catch (JsonProcessingException e) {
//			e.printStackTrace();
//		}

			var asm = new Assembler(data);

			Assembler.writeLinesToFile("object_code.txt", asm.getObjectCode());
		} catch (FileParserException e) {
			Assembler.writeLinesToFile("object_code.txt", Lists.newArrayList(e.getMessage()));
			Assembler.writeLinesToFile("spec_error_report.txt", e.getErrorReport());
			System.exit(1);
		} catch (AssemblerException | IOException e) {
			System.exit(1);
		}
	}
}
