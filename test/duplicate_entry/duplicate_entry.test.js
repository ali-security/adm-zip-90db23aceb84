"use strict";

// GHSA-p634-w6r4-rjp2: a ZIP archive can declare the same entry name twice.
// adm-zip kept every entry in its entry list (used by extractAllTo/getEntries)
// but only the last one in its name table (used by getEntry/readFile), so a
// validate-then-extract workflow could approve one file's content through
// getEntry() while extractAllTo() wrote a different file's bytes under that
// same name. Archives with duplicate entry names are now rejected on load.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");

// The advisory's PoC archive: "a.txt" ("FIRST") and "b.txt" ("SECOND"), with
// the "a.txt" name bytes (local header and central directory record) then
// rewritten to "b.txt", so the central directory lists "b.txt" twice.
function duplicateNameArchive() {
    const zip = new Zip();
    zip.addFile("a.txt", Buffer.from("FIRST"));
    zip.addFile("b.txt", Buffer.from("SECOND"));
    const buf = Buffer.from(zip.toBuffer());

    const from = Buffer.from("a.txt");
    const to = Buffer.from("b.txt");
    let replaced = 0;
    for (let i = buf.indexOf(from); i !== -1; i = buf.indexOf(from, i + from.length)) {
        to.copy(buf, i);
        replaced++;
    }
    // one local file header + one central directory record
    assert.strictEqual(replaced, 2);
    return buf;
}

describe("ADM-ZIP - duplicate entry names (GHSA-p634-w6r4-rjp2)", () => {
    let destination;

    beforeEach(() => {
        destination = fs.mkdtempSync(path.join(os.tmpdir(), "adm-zip-duplicate-"));
    });

    afterEach(() => {
        rimraf.sync(destination);
    });

    it("getEntry() fails closed instead of approving the last duplicate", () => {
        const zip = new Zip(duplicateNameArchive(), { noSort: true });
        let approved = null;
        assert.throws(() => {
            // before the fix this returned "SECOND" while extractAllTo() wrote "FIRST"
            approved = zip.getEntry("b.txt").getData().toString();
        }, /Duplicate entry name/);
        assert.strictEqual(approved, null);
    });

    it("readFile() and getEntries() reject the archive", () => {
        assert.throws(() => new Zip(duplicateNameArchive(), { noSort: true }).readFile("b.txt"), /Duplicate entry name/);
        assert.throws(() => new Zip(duplicateNameArchive(), { noSort: true }).getEntries(), /Duplicate entry name/);
    });

    it("rejects the archive at load time when readEntries is enabled", () => {
        assert.throws(() => new Zip(duplicateNameArchive(), { noSort: true, readEntries: true }), /Duplicate entry name/);
    });

    it("extractAllTo() throws without writing either duplicate to disk", () => {
        const zip = new Zip(duplicateNameArchive(), { noSort: true });
        assert.throws(() => zip.extractAllTo(destination, true), /Duplicate entry name/);
        assert.strictEqual(fs.existsSync(path.join(destination, "b.txt")), false);
    });

    it("extractAllToAsync() rejects without writing either duplicate to disk", async () => {
        const zip = new Zip(duplicateNameArchive(), { noSort: true });
        await assert.rejects(zip.extractAllToAsync(destination, true), /Duplicate entry name/);
        assert.strictEqual(fs.existsSync(path.join(destination, "b.txt")), false);
    });

    it("the same archive without the renamed entry still loads and extracts", () => {
        const zip = new Zip();
        zip.addFile("a.txt", Buffer.from("FIRST"));
        zip.addFile("b.txt", Buffer.from("SECOND"));
        const reopened = new Zip(zip.toBuffer(), { noSort: true });
        assert.strictEqual(reopened.getEntry("b.txt").getData().toString(), "SECOND");
        reopened.extractAllTo(destination, true);
        assert.strictEqual(fs.readFileSync(path.join(destination, "a.txt"), "utf8"), "FIRST");
        assert.strictEqual(fs.readFileSync(path.join(destination, "b.txt"), "utf8"), "SECOND");
    });

    it("distinct names sharing a basename or matching Object.prototype keys are not duplicates", () => {
        const zip = new Zip();
        zip.addFile("dir1/b.txt", Buffer.from("one"));
        zip.addFile("dir2/b.txt", Buffer.from("two"));
        zip.addFile("toString", Buffer.from("t"));
        zip.addFile("hasOwnProperty", Buffer.from("h"));
        zip.addFile("__proto__", Buffer.from("p"));
        const reopened = new Zip(zip.toBuffer(), { readEntries: true });
        assert.strictEqual(reopened.getEntries().length, 5);
        assert.strictEqual(reopened.readFile("dir1/b.txt").toString(), "one");
        assert.strictEqual(reopened.readFile("dir2/b.txt").toString(), "two");
        assert.strictEqual(reopened.readFile("toString").toString(), "t");
        assert.strictEqual(reopened.readFile("hasOwnProperty").toString(), "h");
        assert.strictEqual(reopened.readFile("__proto__").toString(), "p");
    });
});
