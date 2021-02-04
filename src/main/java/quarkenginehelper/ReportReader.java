package quarkenginehelper;

import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;

import com.google.gson.stream.JsonReader;

import quarkenginehelper.QuarkReport.Crime;
import quarkenginehelper.QuarkReport.Method;
import quarkenginehelper.QuarkReport.Node;

public class ReportReader {

	public static QuarkReport parseReport(FileReader in) throws IOException {
		JsonReader reader = new JsonReader(in);
		QuarkReport report = new QuarkReport();

		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			switch (name) {
			case "md5":
				report.md5 = reader.nextString();
				break;
			case "apk_filename":
				report.filename = reader.nextString();
				break;
			case "total_score":
				report.totalScore = reader.nextDouble();
				break;
			case "crimes":
				readCrimeArray(reader, report);
				break;
			default:
				reader.skipValue();
			}
		}
		reader.endObject();
		return report;
	}

	public static void readCrimeArray(JsonReader reader, QuarkReport report) throws IOException {
		reader.beginArray();
		while (reader.hasNext())
			report.crimes.add(readCrime(reader, report));
		reader.endArray();
	}

	protected static Crime readCrime(JsonReader reader, QuarkReport report) throws IOException {
		Crime crime = new Crime();

		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			switch (name) {
			case "crime":
				crime.description = reader.nextString();
				break;
			case "score":
				crime.score = reader.nextDouble();
				break;
			case "weight":
				crime.weight = reader.nextDouble();
				break;
			case "confidence":
				crime.confidence = reader.nextString();
				break;
			case "permissions":
				crime.permissions = readPermissionArray(reader);
				break;
			case "native_api":
			case "combination":
				crime.nativeAPI = readMethodArray(reader);
				break;
			case "sequence":
				reader.skipValue();
				break;
			case "register":
				readInvocationArray(reader, crime, report);
				break;
			default:
				reader.skipValue();
			}
		}
		reader.endObject();
		return crime;
	}

	protected static String[] readPermissionArray(JsonReader reader) throws IOException {
		var tempList = new ArrayList<String>();

		reader.beginArray();
		while (reader.hasNext())
			tempList.add(reader.nextString());
		reader.endArray();
		return tempList.toArray(new String[] {});
	}

	public static Method[] readMethodArray(JsonReader reader) throws IOException {
		var tempList = new ArrayList<Method>();

		reader.beginArray();
		while (reader.hasNext())
			tempList.add(readMethod(reader));
		reader.endArray();
		return tempList.toArray(new Method[] {});
	}

	protected static Method readMethod(JsonReader reader) throws IOException {
		String className = "";
		String methodName = "";
		String descriptor = "";

		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			String value = reader.nextString();
			switch (name) {
			case "class":
				className = value;
				break;
			case "method":
				methodName = value;
				break;
			case "descriptor":
				descriptor = value;
				break;
			default:
			}
		}
		reader.endObject();

		return new Method(className, methodName, descriptor);
	}

	protected static byte[] getBytecode(String insStr) throws IOException {
		insStr = insStr.trim();
		if (insStr.isEmpty())
			return null;

		String[] insArr = insStr.split(" +");
		byte[] byteArr = new byte[insArr.length];

		try {
			for (int i = 0; i < insArr.length; i++)
				byteArr[i] = Integer.valueOf(insArr[i], 16).byteValue();
		} catch (NumberFormatException e) {
			throw new IOException(e);
		}

		return byteArr;
	}

	protected static void readInvocationArray(JsonReader reader, Crime crime, QuarkReport report) throws IOException {
		reader.beginArray();
		while (reader.hasNext())
			report.nodes.add(readInvocation(reader, crime));
		reader.endArray();
	}

	protected static Method parseMethod(String fullname) throws IOException {
		var pieces = fullname.split(" +", 3);
		if (pieces[1].length() == 0 || pieces[2].length() == 0)
			throw new IOException("Illegal Method Name %s".formatted(Arrays.toString(pieces)));

		// Class name
		var className = pieces[0].toCharArray();
		var newClassName = new char[className.length * 2];
		if (className[0] != 'L')
			throw new IOException("Illegal Method Name %s".formatted(Arrays.toString(pieces)));

		var index = 1; // The first char must is 'L'
		var newIndex = 0;
		while (index < className.length && newIndex < newClassName.length) {
			char c = className[index++];
			switch (c) {
			case '/':
				newClassName[newIndex++] = ':';
				newClassName[newIndex++] = ':';
				break;
			case ';':
				break;
			default:
				newClassName[newIndex++] = c;
			}
		}
		return new Method(String.valueOf(newClassName).trim(), pieces[1], pieces[2]);
	}

	protected static Node readInvocation(JsonReader reader, Crime crime) throws IOException {
		Method location = null;
		byte[] first = null;
		byte[] second = null;

		reader.beginObject();
		String fullMethodName = reader.nextName();
		location = parseMethod(fullMethodName);

		reader.beginObject();
		while (reader.hasNext()) {
			String name = reader.nextName();
			switch (name) {
			case "first_hex":
				first = getBytecode(reader.nextString());
				break;
			case "second_hex":
				second = getBytecode(reader.nextString());
				break;
			default:
				reader.skipValue();
			}
		}
		reader.endObject();
		reader.endObject();

		return new Node(crime, location, first, second);
	}

}
