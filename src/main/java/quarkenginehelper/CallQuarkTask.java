package quarkenginehelper;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.Task;
import ghidra.util.task.TaskMonitor;

public final class CallQuarkTask extends Task {

	final String absoluteQuarkPath;
	final String absoluteDexPath;
	final String absoluteReportPath;

	CallQuarkTask(String quarkPath, String dexPath, String reportPath) {
		super("Quark-Engine launching", true, true, false);

		this.absoluteQuarkPath = quarkPath;
		this.absoluteDexPath = dexPath;
		this.absoluteReportPath = reportPath;

		Msg.debug(this, "QuarkPath:" + absoluteQuarkPath);
		Msg.debug(this, "DexPath  :" + absoluteDexPath);
		Msg.debug(this, "ReportPath:" + absoluteReportPath);
	}

	@Override
	public void run(TaskMonitor monitor) throws CancelledException {
		monitor.setShowProgressValue(false);

		monitor.setMessage("Launching Quark-Engine");

		String[] commands = { absoluteQuarkPath, "-a", absoluteDexPath, "-o", absoluteReportPath };
		Process quark = null;
		try {
			quark = new ProcessBuilder().command(commands).redirectErrorStream(true).start();
			BufferedReader quarkStdOutNErr = new BufferedReader(new InputStreamReader(quark.getInputStream()));

			monitor.setMessage("Analyzing File");
			Msg.debug(this, "Executing Quark with following command: ");
			Msg.debug(this, Arrays.toString(commands));
			while (!quark.waitFor(1, TimeUnit.SECONDS)) {
				String line = null;
				while ((line = quarkStdOutNErr.readLine()) != null) {
					monitor.setMessage(line);
					Msg.debug(this, line);

					monitor.checkCanceled();
				}
			}

		} catch (IOException | InterruptedException e) {
			Msg.error(this, "Error on running Quark.", e);
			return;

		} catch (CancelledException e) {
			if (quark != null)
				quark.destroyForcibly();
			Msg.debug(this, "--Cancelled by User--");
			return;

		}

		Msg.debug(this, "--End of Output--");
	}

}
