/**
 * Build the Word version of the report from the generated Markdown.
 *
 *   node scripts/md_to_docx.js
 *
 * Handles the subset of Markdown the report actually uses: ATX headings,
 * soft-wrapped paragraphs, ordered lists with indented continuations, pipe
 * tables, fenced code blocks, block quotes, horizontal rules, and inline
 * bold / italic / code.
 */

const fs = require("fs");
const path = require("path");
const {
  AlignmentType, BorderStyle, Document, HeadingLevel, LevelFormat, Packer,
  Paragraph, ShadingType, Table, TableCell, TableRow, TextRun, WidthType,
} = require("docx");

const ROOT = path.join(__dirname, "..");
const SOURCE = process.argv[2]
  ? path.resolve(process.argv[2])
  : path.join(ROOT, "report", "CSC8214-Report.md");
const TARGET = process.argv[3]
  ? path.resolve(process.argv[3])
  : path.join(ROOT, "report", "CSC8214-Report.docx");

const BODY_FONT = "Calibri";
const MONO_FONT = "Consolas";
const CONTENT_WIDTH = 9026; // A4 width (11906 dxa) less two 1-inch margins

// ---------------------------------------------------------------------------
// Inline formatting
// ---------------------------------------------------------------------------

/** Split `**bold**`, `*italic*` and `` `code` `` into docx TextRuns. */
function inlineRuns(text, base = {}) {
  const runs = [];
  const pattern = /(\*\*[^*]+\*\*|(?<!\*)\*[^*\n]+\*(?!\*)|`[^`]+`)/g;
  let last = 0;

  for (const match of text.matchAll(pattern)) {
    if (match.index > last) {
      runs.push(new TextRun({ text: text.slice(last, match.index), ...base }));
    }
    const token = match[0];
    if (token.startsWith("**")) {
      runs.push(new TextRun({ text: token.slice(2, -2), bold: true, ...base }));
    } else if (token.startsWith("`")) {
      runs.push(new TextRun({
        text: token.slice(1, -1), font: MONO_FONT,
        size: (base.size || 22) - 2, ...base,
      }));
    } else {
      runs.push(new TextRun({ text: token.slice(1, -1), italics: true, ...base }));
    }
    last = match.index + token.length;
  }
  if (last < text.length) {
    runs.push(new TextRun({ text: text.slice(last), ...base }));
  }
  return runs.length ? runs : [new TextRun({ text: "", ...base })];
}

// ---------------------------------------------------------------------------
// Block builders
// ---------------------------------------------------------------------------

const codeLine = (line) => new Paragraph({
  children: [new TextRun({ text: line || " ", font: MONO_FONT, size: 16 })],
  spacing: { before: 0, after: 0, line: 240 },
  shading: { type: ShadingType.CLEAR, fill: "F4F4F4" },
});

const horizontalRule = () => new Paragraph({
  text: "",
  spacing: { before: 120, after: 240 },
  border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: "BBBBBB", space: 1 } },
});

function quoteParagraph(text) {
  return new Paragraph({
    children: inlineRuns(text, { italics: true, size: 20 }),
    indent: { left: 360 },
    spacing: { before: 120, after: 120 },
    border: { left: { style: BorderStyle.SINGLE, size: 12, color: "808080", space: 8 } },
  });
}

/** Pipe table: first row is the header, second is the alignment separator. */
function buildTable(rows) {
  const cells = rows.map((r) =>
    r.replace(/^\|/, "").replace(/\|$/, "").split("|").map((c) => c.trim()));
  const header = cells[0];
  const body = cells.slice(2);
  const columns = header.length;

  // Width each column by the longest cell it holds, clamped so one long cell
  // cannot starve the others, but never narrower than its longest single word
  // -- otherwise a word breaks mid-way. Then normalise to the usable width.
  const weights = Array.from({ length: columns }, (_, i) => {
    const cells = [header, ...body].map((r) => (r[i] || ""));
    const longestCell = Math.max(...cells.map((c) => c.length));
    const longestWord = Math.max(...cells.flatMap((c) => c.split(/\s+/).map((w) => w.length)));
    return Math.max(longestWord * 1.6, Math.min(longestCell, 48), 6);
  });
  const total = weights.reduce((a, b) => a + b, 0);
  const widths = weights.map((w) => Math.round((w / total) * CONTENT_WIDTH));
  widths[columns - 1] += CONTENT_WIDTH - widths.reduce((a, b) => a + b, 0);

  const makeRow = (values, isHeader) => new TableRow({
    tableHeader: isHeader,
    children: values.map((value, i) => new TableCell({
      width: { size: widths[i], type: WidthType.DXA },
      shading: isHeader
        ? { type: ShadingType.CLEAR, fill: "EDEDED" }
        : { type: ShadingType.CLEAR, fill: "FFFFFF" },
      margins: { top: 60, bottom: 60, left: 100, right: 100 },
      children: [new Paragraph({
        children: inlineRuns(value, { bold: isHeader || undefined, size: 19 }),
        spacing: { before: 0, after: 0 },
      })],
    })),
  });

  return new Table({
    columnWidths: widths,
    width: { size: CONTENT_WIDTH, type: WidthType.DXA },
    rows: [makeRow(header, true), ...body.map((r) => makeRow(r, false))],
  });
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

function parse(markdown) {
  const lines = markdown.split("\n");
  const blocks = [];
  let paragraph = [];
  let listInstance = 0;
  let inList = false;

  const flushParagraph = () => {
    if (!paragraph.length) return;
    blocks.push(new Paragraph({
      children: inlineRuns(paragraph.join(" ")),
      spacing: { before: 0, after: 140, line: 276 },
      alignment: AlignmentType.JUSTIFIED,
    }));
    paragraph = [];
  };

  for (let i = 0; i < lines.length; i += 1) {
    const line = lines[i];

    if (line.startsWith("```")) {                       // fenced code block
      flushParagraph();
      inList = false;
      const body = [];
      i += 1;
      while (i < lines.length && !lines[i].startsWith("```")) {
        body.push(lines[i]);
        i += 1;
      }
      blocks.push(new Paragraph({ text: "", spacing: { before: 60, after: 0 } }));
      body.forEach((l) => blocks.push(codeLine(l)));
      blocks.push(new Paragraph({ text: "", spacing: { before: 0, after: 140 } }));
      continue;
    }

    if (line.startsWith("|")) {                         // pipe table
      flushParagraph();
      inList = false;
      const rows = [];
      while (i < lines.length && lines[i].startsWith("|")) {
        rows.push(lines[i]);
        i += 1;
      }
      i -= 1;
      blocks.push(buildTable(rows));
      blocks.push(new Paragraph({ text: "", spacing: { before: 0, after: 140 } }));
      continue;
    }

    const heading = line.match(/^(#{1,4})\s+(.*)$/);
    if (heading) {
      flushParagraph();
      inList = false;
      const depth = heading[1].length;
      const isTitle = depth === 1 && blocks.length === 0;
      blocks.push(new Paragraph({
        children: inlineRuns(heading[2], isTitle ? { size: 36, bold: true } : {}),
        heading: isTitle ? HeadingLevel.TITLE
          : depth === 1 ? HeadingLevel.HEADING_1
            : depth === 2 ? HeadingLevel.HEADING_2 : HeadingLevel.HEADING_3,
        pageBreakBefore: depth === 1 && !isTitle,
      }));
      continue;
    }

    if (line.trim() === "---") {                        // horizontal rule
      flushParagraph();
      inList = false;
      blocks.push(horizontalRule());
      continue;
    }

    if (line.startsWith(">")) {                         // block quote
      flushParagraph();
      inList = false;
      const body = [];
      while (i < lines.length && lines[i].startsWith(">")) {
        body.push(lines[i].replace(/^>\s?/, ""));
        i += 1;
      }
      i -= 1;
      blocks.push(quoteParagraph(body.join(" ").trim()));
      continue;
    }

    const ordered = line.match(/^(\d+)\.\s+(.*)$/);
    if (ordered) {                                      // ordered list item
      flushParagraph();
      if (!inList) {
        listInstance += 1;                              // restart each new list
        inList = true;
      }
      paragraph = [ordered[2]];
      // absorb the indented continuation lines that belong to this item
      while (i + 1 < lines.length && /^\s{3,}\S/.test(lines[i + 1])) {
        paragraph.push(lines[i + 1].trim());
        i += 1;
      }
      blocks.push(new Paragraph({
        children: inlineRuns(paragraph.join(" ")),
        numbering: { reference: "ordered", level: 0, instance: listInstance },
        spacing: { before: 0, after: 120, line: 276 },
      }));
      paragraph = [];
      continue;
    }

    if (line.trim() === "") {
      flushParagraph();
      inList = false;
      continue;
    }

    paragraph.push(line.trim());                        // soft-wrapped prose
  }
  flushParagraph();
  return blocks;
}

// ---------------------------------------------------------------------------

function main() {
  const blocks = parse(fs.readFileSync(SOURCE, "utf8"));

  const headingStyle = (size) => ({
    run: { font: BODY_FONT, size, bold: true, color: "000000" },
    paragraph: { spacing: { before: 280, after: 140 }, keepNext: true },
  });

  const document = new Document({
    creator: "260452597",
    lastModifiedBy: "260452597",
    title: "CSC8214 System Security: Assignment and Report",
    styles: {
      default: {
        document: { run: { font: BODY_FONT, size: 22 } },
        title: {
          run: { font: BODY_FONT, size: 36, bold: true, color: "000000" },
          paragraph: { spacing: { before: 0, after: 240 }, keepNext: true },
        },
        heading1: headingStyle(30),
        heading2: headingStyle(26),
        heading3: headingStyle(23),
      },
    },
    numbering: {
      config: [{
        reference: "ordered",
        levels: [{
          level: 0,
          format: LevelFormat.DECIMAL,
          text: "%1.",
          alignment: AlignmentType.START,
          style: { paragraph: { indent: { left: 460, hanging: 320 } } },
        }],
      }],
    },
    sections: [{
      properties: { page: { margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
      children: blocks,
    }],
  });

  Packer.toBuffer(document).then((buffer) => {
    fs.writeFileSync(TARGET, buffer);
    console.log(`wrote ${path.relative(ROOT, TARGET)} (${blocks.length} blocks, ` +
                `${(buffer.length / 1024).toFixed(0)} KB)`);
  });
}

main();
