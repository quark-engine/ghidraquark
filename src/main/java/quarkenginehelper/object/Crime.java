package quarkenginehelper.object;

public class Crime {
	public String description;
	public float score;
	public float weight;
	public String confidence;
	public String[] permissions;
	public MethodView[] nativeApi;
	public Invocation[] sequence;

	public static class MethodView {
		public String methodName;
		public String className;
		public String dexcripter;
	}

	public static class Bytecode {
		public String mnenic;
		public String register;
		public String parameter;
	}

	public static class Invocation {
		public MethodView parent;
		public Bytecode first;
		public Bytecode second;
	}
}
