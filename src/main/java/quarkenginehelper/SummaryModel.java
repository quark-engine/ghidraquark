package quarkenginehelper;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.CodeUnit;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.util.AddressFieldLocation;
import ghidra.program.util.ProgramLocation;
import ghidra.program.util.ProgramSelection;
import ghidra.util.Msg;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.ProgramLocationTableColumnExtensionPoint;
import ghidra.util.task.TaskMonitor;
import quarkenginehelper.QuarkReport.Method;
import quarkenginehelper.QuarkReport.Node;

public class SummaryModel extends AddressBasedTableModel<Node> {
	private File reportPath;

	public final static int ADDRESS_COL = 0;

	SummaryModel(QuarkEnginePlugin plugin) {
		super("Quark Engine Summary", plugin.getTool(), null, null);
	}

	@Override
	public Address getAddress(int row) {
		return (Address) this.getColumnValueForRow(this.getRowObject(row), ADDRESS_COL);
	}

	public AddressSet getAddressSet(int row) {
		Node node = getRowObject(row);
		byte[][] searchBytes = { node.firstInvocation, node.secondInvocation };

		Object value = getColumnValueForRow(node, ADDRESS_COL);
		if (value == null)
			return null;
		
		Address address = (Address) value;
		if (address.isExternalAddress())
			return null;

		AddressSet set = new AddressSet();
		
		Listing listing = program.getListing();
		Function func = listing.getFunctionAt(address);
		if (func == null) return null;
		
		var iter = func.getBody().getAddresses(true);
		try {
			SEARCH_LOOP: for (byte[] target : searchBytes) {
				while (iter.hasNext()) {
					CodeUnit instruction = listing.getCodeUnitAt(iter.next());
					if (instruction == null) continue;

					Msg.debug(this, instruction.getMnemonicString());

					String mnemonic = instruction.getMnemonicString();
					if (mnemonic.startsWith("return"))
						break SEARCH_LOOP;

					if (mnemonic.startsWith("invoke")) {

						if (Arrays.equals(instruction.getBytes(), target)) {
							set.add(instruction.getAddress());
							break;
						}
					}
				}
			}

		} catch (MemoryAccessException e) {
			Msg.warn(this, "Cannot read instructions in byte.", e);
		}

		return set.getNumAddresses() == 2 ? set : null;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet newSet = new AddressSet();
		for (int element : rows) {
			AddressSet addressSet = getAddressSet(element);
			if (addressSet != null)
				newSet = newSet.union(addressSet);
		}

		return new ProgramSelection(newSet);
	}

	void openFile(File newReportPath) {
		reportPath = newReportPath;
		reload();
	}

	@Override
	protected void doLoad(Accumulator<Node> accumulator, TaskMonitor monitor) throws CancelledException {
		if (reportPath == null) {
			return;
		}

		try (FileReader reader = new FileReader(reportPath);) {
			QuarkReport report = ReportReader.parseReport(reader);

			accumulator.addAll(report.nodes);

		} catch (FileNotFoundException e) {
			Msg.error(this, "Cannot find report file at " + reportPath.getAbsolutePath());
		} catch (IOException e) {
			Msg.error(this, "Error on reading report at " + reportPath.getAbsolutePath(), e);
		}
	}

	@Override
	protected TableColumnDescriptor<Node> createTableColumnDescriptor() {
		TableColumnDescriptor<Node> descriptor = new TableColumnDescriptor<Node>();

		descriptor.addVisibleColumn(new NodeAddressTableColumn(), 1, true);
		descriptor.addVisibleColumn(new NodeDescriptorTableColumn());
		descriptor.addVisibleColumn(new NodeConfidenceTableColumn());
		//descriptor.addVisibleColumn(new NodeBytecodesTableColumn());

		return descriptor;
	}

	public static class NodeAddressTableColumn extends ProgramLocationTableColumnExtensionPoint<Node, Address> {

		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public Address getValue(Node node, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			if (data != null && node.location != null) {
				Method location = node.location;
				List<Function> functions = data.getListing().getFunctions(location.className, location.name);

				// Show the first result
				return functions.size() == 0 ? null : functions.get(0).getEntryPoint();
			}
			return null;
		}

		@Override
		public ProgramLocation getProgramLocation(Node node, Settings settings, Program program,
				ServiceProvider serviceProvider) {
			if (program != null && node.location != null) {
				Method location = node.location;
				List<Function> functions = program.getListing().getFunctions(location.className, location.name);

				if (functions.size() == 0)
					return null;

				return new AddressFieldLocation(program, functions.get(0).getEntryPoint());

			}
			return null;

		}
	}

	private static class NodeDescriptorTableColumn extends AbstractProgramBasedDynamicTableColumn<Node, String> {

		@Override
		public String getColumnName() {
			return "High Potential Risk";
		}

		@Override
		public String getValue(Node node, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			return node.crime.description;
		}
	}

	private static class NodeConfidenceTableColumn extends AbstractProgramBasedDynamicTableColumn<Node, String> {

		@Override
		public String getColumnName() {
			return "Confidence";
		}

		@Override
		public String getValue(Node node, Settings settings, Program data, ServiceProvider serviceProvider)
				throws IllegalArgumentException {
			return node.crime.confidence;
		}

	}

//	private static class NodeBytecodesTableColumn extends AbstractProgramBasedDynamicTableColumn<Node, String> {
//
//		@Override
//		public String getColumnName() {
//			return "Bytecodes";
//		}
//
//		@Override
//		public String getValue(Node node, Settings settings, Program data, ServiceProvider serviceProvider)
//				throws IllegalArgumentException {
//			return Arrays.toString(node.firstInvocation) + Arrays.toString(node.secondInvocation);
//		}
//
//	}

}
