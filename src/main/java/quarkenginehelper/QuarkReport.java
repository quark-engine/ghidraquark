package quarkenginehelper;

import java.util.ArrayList;
import java.util.List;

public class QuarkReport {
	public String md5;
	public String filename;
	public double totalScore;

	public List<Crime> crimes;
	public List<Node> nodes;

	public static class Crime {
		public String description;
		public double score;
		public double weight;
		public String confidence;
		public String[] permissions;
		public Method[] nativeAPI;
	}

	public static class Method {
		public final String className;
		public final String name;
		public final String descriptor;

		public Method(String className, String name, String descriptor) {
			super();
			this.className = className;
			this.name = name;
			this.descriptor = descriptor;
		}
	}

	public static class Node {
		public final Crime crime;

		public final Method location;

		public final byte[] firstInvocation;
		public final byte[] secondInvocation;

		public Node(Crime crime, Method location, byte[] firstInvocation, byte[] secondInvocation) {
			super();
			this.crime = crime;
			this.location = location;
			this.firstInvocation = firstInvocation;
			this.secondInvocation = secondInvocation;
		}
	}
	
	public QuarkReport() {
		crimes = new ArrayList<Crime>();
		nodes = new ArrayList<Node>();
	}
}