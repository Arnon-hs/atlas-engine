export function render(value) {
  return value.toString();
}

export class Browser {
  constructor(name) { this.name = name; }
  evaluate(source) { return eval(source); }
}

// This occurrence is only a comment: eval(untrusted)
const text = 'child_process.exec(untrusted)';
