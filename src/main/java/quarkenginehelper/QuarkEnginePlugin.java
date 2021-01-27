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
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.FileSystems;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import javax.swing.SwingWorker;

import org.python.antlr.ast.Assert.msg_descriptor;

import com.google.gson.JsonObject;
import com.google.gson.stream.JsonReader;

import edu.uci.ics.jung.visualization.transform.shape.MagnifyShapeTransformer;
import ghidra.app.ExamplesPluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskDialog;
import ghidra.util.task.TaskMonitor;
import ghidra.util.worker.Job;
import ghidra.util.worker.Worker;

/**
 * TODO: Provide class-level documentation that describes what this plugin does.
 */
//@formatter:off
@PluginInfo(
	status = PluginStatus.STABLE,
	packageName = ExamplesPluginPackage.NAME,
	category = PluginCategoryNames.ANALYSIS,
	shortDescription = "Quark Engine Helper short description goes here.",
	description = "Plugin long description goes here."
)
//@formatter:on
public class QuarkEnginePlugin extends ProgramPlugin {

	// Program
	Program program;
	
	// Basic info
	String absoluteDexPath;
	String absoluteRuleDirectory = "C:\\Users\\cinde\\Documents\\quark-APKLab\\quark-rules";
	String absoluteReportPath;
	String absoluteQuarkPath;
	
	// I/O
	BufferedReader quarkStdOutNErr;
	
	//Report
	JsonObject report;
	
	// User interfaces
	SummaryTableProvider summaryTable;
	RuleProvider ruleWindow;

	/**
	 * Plugin constructor.
	 * 
	 * @param tool The plugin tool that this plugin is added to.
	 */
	public QuarkEnginePlugin(PluginTool tool) {
		super(tool, true, true);
		
		String pluginName = getName();
		ruleWindow = new RuleProvider(this, pluginName);
		//summaryTable = new SummaryTableProvider(this, pluginName);
	}
	
	private String findQuarkPath() {
		int timeout = 2; // 5 seconds
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
	
	public void runQuark() {
		Msg.debug(this, "Program :"+program);
		Msg.debug(this, "Dex     :"+absoluteDexPath);
		Msg.debug(this, "Rules   :"+absoluteRuleDirectory);
		Msg.debug(this, "Report  :"+absoluteReportPath);
		Msg.debug(this, "Quark   :"+absoluteQuarkPath);
		
		TaskDialog dialog = new TaskDialog("Analysing", true, false, false);
		Worker worker = new Worker("Quark Worker", dialog);
		worker.schedule( new Job() {
			@Override
			public void run(TaskMonitor monitor) throws CancelledException {
				callQuark(monitor);
			}
		});
		dialog.show(0);
	}
	
	public JsonObject callQuark(TaskMonitor monitor) {
		
		if (absoluteQuarkPath == null) {
//			Msg.showError(this, dialog.getComponent(), "Error", "Cannot find Qaurk installation in path.");
			return null;
		}
		
		monitor.setMaximum(3);
		
		monitor.setMessage("Calling Quark-Engine");
		
		String[] commands = {absoluteQuarkPath, "-a", absoluteDexPath, "-o", absoluteReportPath};
		Process quark = null;
		try {
			quark = new ProcessBuilder().command(commands).redirectErrorStream(true).start();
			quarkStdOutNErr = new BufferedReader(new InputStreamReader(quark.getInputStream()));
			
			monitor.incrementProgress(1);
			monitor.setMessage("Analyzing File");
			Msg.debug(this, "Calling Quark with following command: ");
			Msg.debug(this, Arrays.toString(commands));
			while(!quark.waitFor(1, TimeUnit.SECONDS)) {
				String line = null;
				while((line=quarkStdOutNErr.readLine())!=null)
					Msg.debug(this, ">"+line);
				
				monitor.checkCanceled();
			}
			
		}catch(IOException | InterruptedException e) {
//			Msg.showError(this, monitor.getComponent(), "Error", "Error on running Quark.");
//			dialog.close();
			return null;
			
		}catch(CancelledException e) {
			if ( quark != null)
				quark.destroyForcibly();
			Msg.debug(this, "> --Cancelled by User--");
//			dialog.close();
			return null;
			
		}
		
		Msg.debug(this, "> --End of Output--");
		
		monitor.incrementProgress(1);
		monitor.setMessage("Looking for generated file");
		
		File reportFile = FileSystems.getDefault().getPath(absoluteReportPath).toFile();
		if (!reportFile.exists()) {
//			Msg.showError(this, dialog.getComponent(), "Error", "Generated Report is not in "+absoluteReportPath+". Perhapes it is a bug.");
//			dialog.close();
			return null;
		}
		
		monitor.incrementProgress(1);
		
		try {
			Msg.debug(this, "Generated Report:");
			
			BufferedReader reader = new BufferedReader(new FileReader(reportFile));
			String line = null;
			while((line=reader.readLine())!=null) {
				Msg.debug(this, ">"+line);
				
				monitor.checkCanceled();
			}
		}catch(IOException e) {
//			Msg.showError(this, dialog.getComponent(), "Error", "Error on reading report at " + absoluteReportPath);
//			dialog.close();
			return null;
		}catch(CancelledException e) {
			Msg.debug(this, "> --Cancelled by User --");
//			dialog.close();
			return null;
		}
		
		Msg.debug(this, "> -- End of File --");
		return null;
		
//		dialog.setMessage("Analyzing report file");
//		
//		JsonReader reader = new JsonReader(new FileReader(reportFile));
//		
//		// TODO: Finish class Crimes
		
		
	}

	@Override
	public void init() {
		absoluteQuarkPath = findQuarkPath();
		
		if (absoluteQuarkPath != null)
			Msg.debug(this, "Find Quark at: "+absoluteQuarkPath);
		else
			Msg.error(this, "Unable to find Quark. The plugin will not activate.");
	}
	
	@Override
	public void programOpened(Program p) {
		program = p;
		
		absoluteDexPath = program.getExecutablePath();
		if (System.getProperty("os.name").startsWith("Windows") && absoluteDexPath.startsWith("\\" )){
			absoluteDexPath = absoluteDexPath.substring(absoluteDexPath.indexOf('\\')+1);
		}
		if (System.getProperty("os.name").startsWith("Windows") && absoluteDexPath.startsWith("/" )){
			absoluteDexPath = absoluteDexPath.substring(absoluteDexPath.indexOf('/')+1);
		}
		
		File projectDir = program.getDomainFile().getProjectLocator().getProjectDir();
		
		absoluteReportPath = Path.of(projectDir.getPath(), "QuarkReport.json").toString();
	}
	
	@Override
	public void programClosed(Program p) {
		program = null;
	}
}
