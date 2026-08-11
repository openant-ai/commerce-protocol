export class CodegenError extends Error {
  constructor(code, message, context = {}) {
    super(message);
    this.name = "CodegenError";
    this.code = code;
    this.context = context;
  }
}

export function fail(code, message, context) {
  throw new CodegenError(code, message, context);
}
