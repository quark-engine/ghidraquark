package quarkenginehelper;

import java.util.List;

public class QuarkReport {
	public String md5;
	public String filename;
	public double totalScore;

	public List<Crime> crimes;

	public static class Crime {
		public String description;
		public double score;
		public double weight;
		public String confidence;
		public String[] permissions;
		public MethodView[] nativeApi;
		public Invocation[] sequence;
	}

	public static class MethodView {
		public String methodName;
		public String className;
		public String descripter;
	}

	public static class Bytecode {
		public String mnenic;
		public String[] register;
		public String parameter;
	}

	public static class Invocation {
		public MethodView parent;
		public Bytecode first;
		public Bytecode second;
	}
}