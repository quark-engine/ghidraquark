package quarkenginehelper;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.io.File;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.ListSelectionModel;

import docking.WindowPosition;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

public class SummaryProvider extends ComponentProviderAdapter {

	private JPanel mainPanel;
	private SummaryTable reportTable;
	private SummaryModel reportModel;

//	private DockingAction selectionNavigating;
//	private DockingAction makeProgramSelecting;

	private final QuarkEnginePlugin plugin;

	public SummaryProvider(QuarkEnginePlugin plugin) {
		super(plugin.getTool(), "Quark-Engine", plugin.getName());
		this.plugin = plugin;

		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setSubTitle("Summary Report");
		setIcon(QuarkEnginePlugin.ICON);

		buildPanel();
		createActions();
	}

	private void createActions() {
//		selectionNavigating = new SelectionNavigationAction(plugin, reportTable);
//		dockingTool.addLocalAction(this, selectionNavigating);
//
//		makeProgramSelecting = new MakeProgramSelectionAction(plugin, reportTable);
//		dockingTool.addLocalAction(this, makeProgramSelecting);
	}

	private void buildPanel() {
		mainPanel = new JPanel(new BorderLayout(5, 5));
		reportModel = new SummaryModel(plugin);
		reportTable = new SummaryTable(reportModel);

		reportTable.setAutoLookupColumn(SummaryModel.ADDRESS_COL);
		reportTable.setRowSelectionAllowed(true);
		reportTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		reportTable.getSelectionModel().addListSelectionListener(e -> tool.contextChanged(this));
		reportTable.setNavigateOnSelectionEnabled(true);

		var scroller = new JScrollPane(reportTable);
		scroller.setPreferredSize(new Dimension(200, 100));

		mainPanel.add(scroller, BorderLayout.CENTER);
	}

	void setEnable(Program newProgram) {
		reportModel.setProgram(newProgram);
		reportModel.reload();

//		selectionNavigating.setEnabled(true);
//		makeProgramSelecting.setEnabled(true);
	}

	void setDisable() {
		reportModel.setProgram(null);
		reportModel.reload();

//		selectionNavigating.setEnabled(false);
//		makeProgramSelecting.setEnabled(false);
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

	SummaryTable getTable() {
		return reportTable;
	}

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}
