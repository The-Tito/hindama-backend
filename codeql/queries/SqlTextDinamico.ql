/**
 * @name SQL construido dinámicamente en sqlalchemy.text()
 * @description Pasar a text() un string armado con f-string, +, % o .format()
 *              permite inyección SQL. Usa parámetros enlazados (:param).
 * @kind problem
 * @problem.severity error
 * @security-severity 8.8
 * @precision high
 * @id py/hindama/sqlalchemy-text-dinamico
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.ApiGraphs

/** Llamadas a sqlalchemy.text() o sqlalchemy.sql.text() */
API::CallNode llamadaText() {
  result = API::moduleImport("sqlalchemy").getMember("text").getACall()
  or
  result = API::moduleImport("sqlalchemy").getMember("sql").getMember("text").getACall()
}

/** El argumento es un string construido dinámicamente */
predicate esStringDinamico(Expr e, string variante) {
  e instanceof Fstring and variante = "f-string"
  or
  e.(BinaryExpr).getOp() instanceof Add and variante = "concatenación (+)"
  or
  e.(BinaryExpr).getOp() instanceof Mod and variante = "formato con %"
  or
  e.(Call).getFunc().(Attribute).getName() = "format" and variante = ".format()"
}

from API::CallNode call, Expr arg, string variante
where
  call = llamadaText() and
  arg = call.getArg(0).asExpr() and
  esStringDinamico(arg, variante)
select call,
  "SQL dinámico (" + variante + ") pasado a sqlalchemy.text(): usa parámetros enlazados (:param)."
