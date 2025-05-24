import chalk from "chalk";
import morgan from "morgan";

morgan.token("coloured-method", (req) => {
  switch (req.method) {
    case "GET":
      return chalk.green(req.method);
    case "POST":
      return chalk.blue(req.method);
    case "PUT":
      return chalk.yellow(req.method);
    case "DELETE":
      return chalk.red(req.method);
    case "PATCH":
      return chalk.cyan(req.method);
    default:
      return chalk.white(req.method);
  }
});

export default morgan;