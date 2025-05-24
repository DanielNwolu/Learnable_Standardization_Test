import handlebars from 'handlebars';

export function compileTemplateRaw(raw: string, context: object): string {
  return handlebars.compile(raw)(context);
}