package quarkenginehelper;

import ghidra.app.nav.Navigatable;
import ghidra.app.services.GoToService;
import ghidra.util.table.GhidraTable;

public class SummaryTable extends GhidraTable {

	protected Navigatable navigatable;

	public SummaryTable(SummaryModel model) {
		super(model);
	}

	@Override
	public void installNavigation(GoToService newGoToService, Navigatable nav) {
		super.installNavigation(newGoToService, nav);

		navigatable = nav;
	}

	@Override
	public void navigate(int row, int column) {
		super.navigate(row, column);
		if (navigatable == null || row < 0 || column < 0 || !(dataModel instanceof SummaryModel)) {
			return;
		}

		column = convertColumnIndexToModel(column);

		var model = (SummaryModel) dataModel;
		var selection = model.getProgramSelection(new int[] { row });
		if (selection.getMinAddress() != null && selection.getMinAddress().isMemoryAddress()) {
			navigatable.setSelection(selection);
		}
	}

	@Override
	public void removeNavigation() {
		super.removeNavigation();
		navigatable = null;
	}
}
