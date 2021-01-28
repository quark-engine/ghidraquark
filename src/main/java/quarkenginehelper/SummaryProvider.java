package quarkenginehelper;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.File;

import javax.swing.ImageIcon;
import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import docking.ActionContext;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import docking.widgets.filechooser.GhidraFileChooser;
import docking.widgets.filechooser.GhidraFileChooserMode;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.filechooser.ExtensionFileFilter;
import ghidra.util.table.GhidraTable;
import resources.Icons;
import resources.ResourceManager;

public class SummaryProvider extends ComponentProviderAdapter {

	private JPanel mainPanel;
	private GhidraTable reportTable;
	private SummaryModel reportModel;

	private DockingAction launchQuark;
	private DockingAction openReport;

	private GhidraFileChooser chooser;

	private final QuarkEnginePlugin plugin;

	private final ImageIcon icon = ResourceManager.loadImage("images/quark-icon.png");

	public SummaryProvider(QuarkEnginePlugin plugin) {
		super(plugin.getTool(), "Quark-Engine", plugin.getName());
		this.plugin = plugin;

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setSubTitle("Summary Report");
		setIcon(icon);

		buildPanel();
		createActions();

		setVisible(true);
	}

	private void initChooser() {
		if (chooser == null) {
			chooser = new GhidraFileChooser(plugin.getTool().getActiveWindow());

			var filter = ExtensionFileFilter.forExtensions("Quark-Enging Report", "json");
			chooser.addFileFilter(filter);
			chooser.setSelectedFileFilter(filter);

			chooser.setFileSelectionMode(GhidraFileChooserMode.FILES_ONLY);
			chooser.setMultiSelectionEnabled(false);
			chooser.setTitle("Select Report to import");
		}
	}

	private void buildPanel() {
		mainPanel = new JPanel(new BorderLayout(5, 5));
		reportModel = new SummaryModel(plugin);
		reportTable = new GhidraTable(reportModel);

		reportTable.setAutoLookupColumn(SummaryModel.ADDRESS_COL);
		reportTable.setRowSelectionAllowed(true);
		reportTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		reportTable.getSelectionModel().addListSelectionListener(e -> tool.contextChanged(this));
		reportTable.setNavigateOnSelectionEnabled(true);

		var scroller = new JScrollPane(reportTable);
		scroller.setPreferredSize(new Dimension(200, 100));

		mainPanel.add(scroller, BorderLayout.CENTER);
	}

	private void createActions() {
		// Action for user to launch Quark
		launchQuark = new DockingAction("Launch Quark Analysis", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.callQuarkTask();
			}
		};
		launchQuark.setToolBarData(new ToolBarData(icon, null));
		launchQuark.setEnabled(false);
		launchQuark.markHelpUnnecessary();
		dockingTool.addAction(launchQuark);

		// Action for user to open a Quark report.
		openReport = new DockingAction("Open a report", getOwner()) {

			@Override
			public void actionPerformed(ActionContext context) {
				initChooser();
				File selected = chooser.getSelectedFile();
				if (selected != null)
					openFile(selected);
			}

		};
		openReport.setToolBarData(new ToolBarData(Icons.OPEN_FOLDER_ICON, null));
		openReport.setEnabled(false);
		openReport.markHelpUnnecessary();
		dockingTool.addAction(openReport);
	}

	void setEnable(Program newProgram) {
		reportModel.setProgram(newProgram);
		reportModel.reload();

		launchQuark.setEnabled(true);
		openReport.setEnabled(true);
	}

	void setDisable() {
		reportModel.setProgram(null);
		reportModel.reload();

		launchQuark.setEnabled(false);
		openReport.setEnabled(false);
	}

	void openFile(File jsonReport) {
		if (jsonReport.exists()) {
			reportModel.openFile(jsonReport);
			setVisible(true);
		} else {
			Msg.error(this, "Cannot find generated report.");
		}
	}

	void setGoToService(GoToService service) {
		reportTable.installNavigation(service, service.getDefaultNavigatable());
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}
