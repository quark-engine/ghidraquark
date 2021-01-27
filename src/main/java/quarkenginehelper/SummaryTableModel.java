package quarkenginehelper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import docking.widgets.table.AbstractGTableModel;
import quarkenginehelper.object.Crime;

public class SummaryTableModel extends AbstractGTableModel<Crime> {

	private List<Crime> list;
	
	SummaryTableModel(){
		list = new ArrayList<Crime>();
	}
	
	public void addCrimes(Collection<? extends Crime> crimes) {
		list.addAll(crimes);
		this.refresh();
	}
	
	@Override
	public String getName() {
		return this.getClass().toString();
	}

	@Override
	public List<Crime> getModelData() {
		return list;
	}

	@Override
	public Object getColumnValueForRow(Crime t, int columnIndex) {
		switch(columnIndex) {
		case 0:
			return t.description;
		case 1:
			return t.confidence;
		default:
			return null;
		}
	}

	@Override
	public int getColumnCount() {
		return 2; 
	}


}
