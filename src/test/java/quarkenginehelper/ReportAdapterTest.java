package quarkenginehelper;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ReportAdapterTest {

	private FileReader source;
	private ReportReader adapter;
	
	@Before
	public void setUp() throws Exception {
		source = new FileReader(new File("sample/SampleReport.json"));
		adapter = new ReportReader();
	}

	@After
	public void tearDown() throws Exception {
		if (source!=null) {
			source.close();
		}
	}

	@Test
	public void testParseReport() {
		try {
			QuarkReport report = adapter.parseReport(source);
			assertNotNull(report);
		}catch(IOException e) {
			assert false;
		}
	}

}
