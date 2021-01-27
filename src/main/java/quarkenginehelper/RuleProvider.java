package quarkenginehelper;

import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.Tool;
import docking.action.DockingAction;
import docking.action.ToolBarData;
import ghidra.framework.plugintool.Plugin;
import resources.Icons;

public class RuleProvider extends ComponentProvider {

	private JPanel panel;
	
	private DockingAction addRules;
	private DockingAction launchQuark;
	
	private final QuarkEnginePlugin plugin;
	
	private static final String PANNEL_NAME = "Rules";
	
	public RuleProvider(QuarkEnginePlugin plugin, String owner) {
		super(plugin.getTool(), PANNEL_NAME, owner);
		
		this.plugin = plugin;
		
		buildPanel();
		creatActions();
	}
	
	
	private void buildPanel() {
		panel = new JPanel();
		
		JLabel label = new JLabel("Test");
		panel.add(label);
		setVisible(true);
	}
	
	private void creatActions() {
		launchQuark = new DockingAction("Launch Quark", plugin.getName()) {
			@Override
			public void actionPerformed(ActionContext context) {
				plugin.runQuark();
			}
		};
		
		launchQuark.setToolBarData(new ToolBarData(Icons.ADD_ICON, null));
		launchQuark.setEnabled(true);
		launchQuark.markHelpUnnecessary();
		
		dockingTool.addLocalAction(this, launchQuark);
	}

	@Override
	public JComponent getComponent() {
		return panel;
	}

}
