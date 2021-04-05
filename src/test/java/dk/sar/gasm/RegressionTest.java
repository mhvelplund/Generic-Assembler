package dk.sar.gasm;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.List;

import org.junit.Test;

import com.google.common.collect.Lists;

import dk.sar.gasm.data.DataSource;

@SuppressWarnings("deprecation")
public class RegressionTest {
	private void assemblerRegressionTest(List<String> expected, DataSource data) throws Exception {
		try {
			var assembler = new Assembler(data);
			var objectCode = assembler.getObjectCode();
			assertEquals(expected, objectCode);
		} catch (Throwable e) {
			throw new Exception("Failed assemblerRegressionTest", e);
		}
	}

	private DataSource fileParserRegressionTest(String specName, String assemblyName) throws Exception {
		try {
			var spec = getClass().getClassLoader().getResource(specName).getFile();
			var assembly = getClass().getClassLoader().getResource(assemblyName).getFile();
			var file = new FileParser(spec, assembly);
			var data = file.getData();
			assertNotNull(data);
			return data;
		} catch (Throwable e) {
			throw new Exception("Failed fileParserRegressionTest", e);
		}
	}

	@Test
	public void testHelloWorldExample() throws Exception {
		var specName = "HelloWorldExample/HelloWorldMipsSpec.txt";
		var assemblyName = "HelloWorldExample/HelloWorldMipsAssembly.txt";
		var data = fileParserRegressionTest(specName, assemblyName);
		List<String> expected = Lists.newArrayList(
			"0:         48 65 6C 6C 6F 20 57 6F 72 6C 64 ",
			"b:         24 02 00 04 ",
			"f:         3C 01 10 01 ",
			"13:        34 24 00 00 ",
			"17:        00 00 00 0C "
		);
		assemblerRegressionTest(expected, data);
	}

	@Test
	public void testMIPS() throws Exception {
		var specName = "MIPS/mipsspec.txt";
		var assemblyName = "MIPS/mipsassembly.txt";
		var data = fileParserRegressionTest(specName, assemblyName);
		List<String> expected = Lists.newArrayList(
			"0:         48 65 6C 6C 6F 2C 20 57 6F 72 6C 64 ",
			"c:         24 02 00 04 ",
			"10:        3C 01 10 01 ",
			"14:        34 24 00 00 ",
			"18:        00 00 00 0C "
		);
		assemblerRegressionTest(expected, data);
	}

	@Test
	public void testMotorola68K() throws Exception {
		var specName = "Moto68000/68kspec.txt";
		var assemblyName = "Moto68000/68kassembly.txt";
		var data = fileParserRegressionTest(specName, assemblyName);
		List<String> expected = Lists.newArrayList(
			"0:         4E 56 00 C8 ",
			"4:         4E 56 00 64 ",
			"8:         4E 56 00 32 ",
			"c:         60 F2 "
		);
		assemblerRegressionTest(expected, data);
	}

	@Test(expected = Exception.class)
	public void testSkeleton() throws Exception {
		var specName = "skeleton/skeleton_spec.txt";
		var assemblyName = "skeleton/skeleton_assembly.txt";
		fileParserRegressionTest(specName, assemblyName);
	}

	@Test
	public void testX86() throws Exception {
		var specName = "x86/x86spec.txt";
		var assemblyName = "x86/x86assembly.txt";
		var data = fileParserRegressionTest(specName, assemblyName);
		List<String> expected = Lists.newArrayList(
			"0:         01 C1 ",
			"2:         03 3B ",
			"4:         03 9D 01 00 00 00 ",
			"a:         03 2C 05 05 00 00 00 ",
			"11:        03 15 78 00 00 00 ",
			"17:        03 0C BB ",
			"1a:        EB E8 "
		);
		assemblerRegressionTest(expected, data);
	}
}
