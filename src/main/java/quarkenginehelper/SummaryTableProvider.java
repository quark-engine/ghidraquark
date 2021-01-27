package quarkenginehelper;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import docking.ComponentProvider;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.framework.plugintool.Plugin;
import ghidra.util.table.GhidraTable;
import ghidra.util.table.GhidraThreadedTablePanel;
import quarkenginehelper.object.Crime;

public class SummaryTableProvider extends ComponentProvider {

	private GhidraTable summaryTable;
	
	private final Plugin plugin;

	private JPanel workPanel;
	
	private final static String PANNEL_NAME = "Summary Report";
	
	public SummaryTableProvider(Plugin plugin, String owner) {
		super(plugin.getTool(), PANNEL_NAME, owner);
		
		this.plugin = plugin;
		
		buildPanel();
		setVisible(true);
	}
	
	private void buildPanel() {
		
		workPanel = new JPanel();
		
		var summaryModel = new SummaryTableModel();
		summaryTable = new GhidraTable(summaryModel);
		
		workPanel.add(new JScrollPane(summaryTable));
	}
	
	public void addCrime(Crime crime) {
		
	}

	@Override
	public JComponent getComponent() {
		return workPanel;
	}

}
