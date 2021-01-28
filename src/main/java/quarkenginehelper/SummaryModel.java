package quarkenginehelper;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.List;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.ProgramLocationTableColumnExtensionPoint;
import ghidra.util.task.TaskMonitor;
import quarkenginehelper.QuarkReport.Crime;
import quarkenginehelper.QuarkReport.Invocation;

public class SummaryModel extends AddressBasedTableModel<Crime> {
	private File reportPath;

	public final static int ADDRESS_COL = 0;

	SummaryModel(QuarkEnginePlugin plugin) {
		super("Quark Engine Summary", plugin.getTool(), null, null);
	}

	@Override
	public Address getAddress(int row) {
		return (Address) this.getColumnValueForRow(this.getRowObject(row), ADDRESS_COL);
	}

	void openFile(File newReportPath) {
		reportPath = newReportPath;
		reload();
	}

	@Override
	protected void doLoad(Accumulator<Crime> accumulator, TaskMonitor monitor) throws CancelledException {
		if (reportPath == null) {
			return;
		}

		try (FileReader reader = new FileReader(reportPath);) {
			QuarkReport report = ReportReader.parseReport(reader);

			accumulator.addAll(report.crimes);

		} catch (FileNotFoundException e) {
			Msg.error(this, "Cannot find report file at " + reportPath.getAbsolutePath());
		} catch (IOException e) {
			Msg.error(this, "Error on reading report at " + reportPath.getAbsolutePath(), e);
		}
	}

	@Override
	protected TableColumnDescriptor<Crime> createTableColumnDescriptor() {
		TableColumnDescriptor<Crime> descriptor = new TableColumnDescriptor<Crime>();

		descriptor.addVisibleColumn(new CrimeAddressTableColumn(), 1, true);
		descriptor.addVisibleColumn(new CrimeDescriptorTableColumn());
		descriptor.addVisibleColumn(new CrimeConfidenceTableColumn());

		return descriptor;
	}

	public static class CrimeAddressTableColumn extends ProgramLocationTableColumnExtensionPoint<Crime, Address> {

		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public Address getValue(Crime rowObject, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			if (data != null && rowObject.sequence.length != 0) {
				Invocation invocation = rowObject.sequence[0];
				List<Function> functions = data.getListing().getFunctions(invocation.parent.className,
						invocation.parent.methodName);

				// Show the first result
				return functions.size() == 0 ? null : functions.get(0).getEntryPoint();
			}
			return null;
		}

		@Override
		public ProgramLocation getProgramLocation(Crime rowObject, Settings settings, Program program,
				ServiceProvider serviceProvider) {
			if (program != null && rowObject.sequence.length != 0) {
				Invocation invocation = rowObject.sequence[0];
				List<Function> functions = program.getListing().getFunctions(invocation.parent.className,
						invocation.parent.methodName);

				if (functions.size() == 0)
					return null;

				return new AddressFieldLocation(program, functions.get(0).getEntryPoint());

			}
			return null;

		}
	}

	private static class CrimeDescriptorTableColumn extends AbstractProgramBasedDynamicTableColumn<Crime, String> {

		@Override
		public String getColumnName() {
			return "High Potential Risk";
		}

		@Override
		public String getValue(Crime rowObject, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			return rowObject.description;
		}
	}

	private static class CrimeConfidenceTableColumn extends AbstractProgramBasedDynamicTableColumn<Crime, String> {

		@Override
		public String getColumnName() {
			return "Confidence";
		}

		@Override
		public String getValue(Crime rowObject, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			return rowObject.confidence;
		}

	}

}
