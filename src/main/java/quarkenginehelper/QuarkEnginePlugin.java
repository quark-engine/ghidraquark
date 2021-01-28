/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package quarkenginehelper;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Path;
import java.util.concurrent.TimeUnit;

import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.Task;
import ghidra.util.task.TaskListener;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	servicesRequired = GoToService.class,
	shortDescription = "Quark Engine Helper short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class QuarkEnginePlugin extends ProgramPlugin implements TaskListener {

	String absoluteQuarkPath;

	// User interfaces
	SummaryProvider summaryProvider;

	// Service
	GoToService goToService;

	public QuarkEnginePlugin(PluginTool tool) {
		super(tool, true, true);
		summaryProvider = new SummaryProvider(this);
	}

	private String findQuarkPath() {
		int timeout = 2; // 2 seconds
		String command[] = { "where", "quark" };

		try {
			Process process = new ProcessBuilder().command(command).start();
			BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));

			boolean exitInTime = process.waitFor(timeout, TimeUnit.SECONDS);
			if (exitInTime & process.exitValue() == 0)
				return reader.readLine();

		} catch (IOException | InterruptedException e) {
			return null;
		}

		return null;
	}

	boolean isSupportedFormat(Program newProgram) {
		return newProgram.getExecutableFormat().equals("Dalvik Executable (DEX)");
	}

	void callQuarkTask() {

		String absoluteDexPath = currentProgram.getExecutablePath();
		if (System.getProperty("os.name").startsWith("Windows")) {
			if (absoluteDexPath.startsWith("\\") || absoluteDexPath.startsWith("/"))
				absoluteDexPath = absoluteDexPath.substring(1);
		}

		File projectDir = currentProgram.getDomainFile().getProjectLocator().getProjectDir();
		String absoluteReportPath = Path.of(projectDir.getPath(), "QuarkReport.json").toString();

		Msg.info(this, "Activating Quark-Engine.");
		CallQuarkTask task = new CallQuarkTask(absoluteQuarkPath, absoluteDexPath, absoluteReportPath);
		task.addTaskListener(this);

		getTool().execute(task);
	}

	@Override
	public void init() {
		goToService = getTool().getService(GoToService.class);
		if (goToService == null) {
			Msg.warn(this, "Quark-Engine Plugin cannot find GoToService. Some features may disappear.");
		} else {
			summaryProvider.setGoToService(goToService);
		}

		absoluteQuarkPath = findQuarkPath();
		if (absoluteQuarkPath != null)
			Msg.debug(this, "Find Quark at: " + absoluteQuarkPath);
		else
			Msg.error(this, "Unable to find Quark. The plugin will not activate.");
	}

	GoToService getGoToService() {
		return goToService;
	}

	@Override
	protected void programOpened(Program newProgram) {
		if (isSupportedFormat(newProgram))
			summaryProvider.setEnable(newProgram);
	}

	@Override
	protected void programClosed(Program newProgram) {
		summaryProvider.setDisable();
	}

	@Override
	public void taskCompleted(Task task) {
		if (task instanceof CallQuarkTask) {
			Msg.info(this, "Analysis of Quark-Engine ended.");

			// Refresh Panel
			File jsonReport = new File(((CallQuarkTask) task).absoluteReportPath);
			summaryProvider.openFile(jsonReport);
		}
	}

	@Override
	public void taskCancelled(Task task) {
		// Do nothing
	}

}
