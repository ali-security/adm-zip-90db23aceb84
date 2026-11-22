"use strict";

// CVE-2026-76845: extraction followed symlinks that already exist inside the
// target directory. sanitize() keeps the entry name textually under the target,
// but a pre-existing symlink (or Windows junction) at "<target>/link" pointing
// elsewhere made an entry such as "link/pwned.txt" land outside the target, and
// a symlinked leaf ("<target>/victim.txt" -> outside file) was written through.
// Every extraction path now refuses to write through a symlink found below the
// target directory.

const assert = require("assert");
const fs = require("fs");
const os = require("os");
const path = require("path");
const rimraf = require("rimraf");
const Zip = require("../../adm-zip");
const Utils = require("../../util/utils");

const isWin = process.platform === "win32";
const IN_THE_WAY = /There is a file in the way/;

// Symlink creation needs a privilege on Windows (and is unsupported on some
// filesystems); report "not possible" so the test can skip instead of failing.
function cannotLink(err) {
    return err && (err.code === "EPERM" || err.code === "EACCES" || err.code === "ENOSYS" || err.code === "EOPNOTSUPP");
}

// Directory link: a junction on Windows (no privilege needed, absolute target).
function linkDir(ctx, target, linkPath) {
    try {
        fs.symlinkSync(path.resolve(target), linkPath, isWin ? "junction" : "dir");
    } catch (err) {
        if (cannotLink(err)) ctx.skip();
        throw err;
    }
}

function linkFile(ctx, target, linkPath) {
    try {
        fs.symlinkSync(path.resolve(target), linkPath, "file");
    } catch (err) {
        if (cannotLink(err)) ctx.skip();
        throw err;
    }
}

// build an archive, then re-open it from its bytes like an untrusted download
function archive(entries) {
    const zip = new Zip();
    entries.forEach((e) => zip.addFile(e[0], e[1] === null ? null : Buffer.from(e[1])));
    return new Zip(zip.toBuffer());
}

describe("ADM-ZIP - symlink in extraction target (CVE-2026-76845)", () => {
    let root;
    let target;
    let outside;

    beforeEach(() => {
        root = fs.mkdtempSync(path.join(os.tmpdir(), "adm-zip-symlink-"));
        target = path.join(root, "target");
        outside = path.join(root, "outside");
        fs.mkdirSync(target);
        fs.mkdirSync(outside);
    });

    afterEach(() => {
        rimraf.sync(root);
    });

    describe("a symlinked directory inside the target", () => {
        it("extractAllTo() does not write a file through it", function () {
            linkDir(this, outside, path.join(target, "link"));
            const zip = archive([["link/pwned.txt", "PWNED"]]);

            assert.throws(() => zip.extractAllTo(target, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("extractAllTo() does not create a directory through it", function () {
            linkDir(this, outside, path.join(target, "link"));
            const zip = archive([["link/newdir/", null]]);

            assert.throws(() => zip.extractAllTo(target, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "newdir")), false);
        });

        it("extractAllTo() rejects a link nested below a real directory", function () {
            fs.mkdirSync(path.join(target, "real"));
            linkDir(this, outside, path.join(target, "real", "link"));
            const zip = archive([["real/link/deep/pwned.txt", "PWNED"]]);

            assert.throws(() => zip.extractAllTo(target, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "deep")), false);
        });

        it("extractEntryTo() does not write a file entry through it", function () {
            linkDir(this, outside, path.join(target, "link"));
            const zip = archive([["link/pwned.txt", "PWNED"]]);

            assert.throws(() => zip.extractEntryTo("link/pwned.txt", target, true, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("extractEntryTo() does not write a renamed entry (outFileName) through it", function () {
            linkDir(this, outside, path.join(target, "link"));
            const zip = archive([["a.txt", "PWNED"]]);

            assert.throws(() => zip.extractEntryTo("a.txt", target, false, true, false, "link/pwned.txt"), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("extractEntryTo() of a directory entry does not write its children through it", function () {
            linkDir(this, outside, path.join(target, "link"));
            const zip = archive([
                ["link/", null],
                ["link/pwned.txt", "PWNED"]
            ]);

            assert.throws(() => zip.extractEntryTo("link/", target, true, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("extractAllToAsync() does not write a file through it", async function () {
            linkDir(this, outside, path.join(target, "link"));
            const zip = archive([["link/pwned.txt", "PWNED"]]);

            await assert.rejects(zip.extractAllToAsync(target, true), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(path.join(outside, "pwned.txt")), false);
        });

        it("extractAllToAsync() does not create a directory through it", async function () {
            linkDir(this, outside, path.join(target, "link"));
            const zip = archive([["link/newdir/", null]]);

            await assert.rejects(zip.extractAllToAsync(target, true));
            assert.strictEqual(fs.existsSync(path.join(outside, "newdir")), false);
        });
    });

    describe("a symlinked file inside the target", () => {
        it("extractAllTo() does not overwrite the file it points to", function () {
            const victim = path.join(outside, "victim.txt");
            fs.writeFileSync(victim, "ORIGINAL");
            linkFile(this, victim, path.join(target, "victim.txt"));
            const zip = archive([["victim.txt", "PWNED"]]);

            assert.throws(() => zip.extractAllTo(target, true), IN_THE_WAY);
            assert.strictEqual(fs.readFileSync(victim, "utf8"), "ORIGINAL");
        });

        it("extractAllTo() does not create the missing file a dangling link points to", function () {
            const victim = path.join(outside, "created.txt");
            linkFile(this, victim, path.join(target, "created.txt"));
            const zip = archive([["created.txt", "PWNED"]]);

            // no overwrite: the dangling link is not "existing", so it used to be followed
            assert.throws(() => zip.extractAllTo(target, false), IN_THE_WAY);
            assert.strictEqual(fs.existsSync(victim), false);
        });

        it("extractEntryTo() does not overwrite the file it points to", function () {
            const victim = path.join(outside, "victim.txt");
            fs.writeFileSync(victim, "ORIGINAL");
            linkFile(this, victim, path.join(target, "victim.txt"));
            const zip = archive([["victim.txt", "PWNED"]]);

            assert.throws(() => zip.extractEntryTo("victim.txt", target, true, true), IN_THE_WAY);
            assert.strictEqual(fs.readFileSync(victim, "utf8"), "ORIGINAL");
        });

        it("extractAllToAsync() does not overwrite the file it points to", async function () {
            const victim = path.join(outside, "victim.txt");
            fs.writeFileSync(victim, "ORIGINAL");
            linkFile(this, victim, path.join(target, "victim.txt"));
            const zip = archive([["victim.txt", "PWNED"]]);

            await assert.rejects(zip.extractAllToAsync(target, true), IN_THE_WAY);
            assert.strictEqual(fs.readFileSync(victim, "utf8"), "ORIGINAL");
        });
    });

    describe("legitimate extraction is unaffected", () => {
        it("extracts into real subdirectories that already exist", async () => {
            fs.mkdirSync(path.join(target, "existing"));
            const zip = archive([
                ["existing/a.txt", "A"],
                ["fresh/b.txt", "B"]
            ]);

            zip.extractAllTo(target, true);
            assert.strictEqual(fs.readFileSync(path.join(target, "existing", "a.txt"), "utf8"), "A");
            assert.strictEqual(fs.readFileSync(path.join(target, "fresh", "b.txt"), "utf8"), "B");

            const asyncTarget = path.join(root, "async");
            fs.mkdirSync(asyncTarget);
            await zip.extractAllToAsync(asyncTarget, true);
            assert.strictEqual(fs.readFileSync(path.join(asyncTarget, "fresh", "b.txt"), "utf8"), "B");

            zip.extractEntryTo("existing/a.txt", target, true, true, false, "renamed.txt");
            assert.strictEqual(fs.readFileSync(path.join(target, "renamed.txt"), "utf8"), "A");
        });

        it("a target directory that is itself reached through a symlink still extracts", async function () {
            const linkedRoot = path.join(root, "linked-root");
            linkDir(this, target, linkedRoot);
            const zip = archive([
                ["dir/", null],
                ["dir/c.txt", "C"]
            ]);

            zip.extractAllTo(linkedRoot, true);
            assert.strictEqual(fs.readFileSync(path.join(target, "dir", "c.txt"), "utf8"), "C");

            const nested = path.join(linkedRoot, "nested");
            await zip.extractAllToAsync(nested, true);
            assert.strictEqual(fs.readFileSync(path.join(target, "nested", "dir", "c.txt"), "utf8"), "C");

            zip.extractEntryTo("dir/c.txt", linkedRoot, false, true);
            assert.strictEqual(fs.readFileSync(path.join(target, "c.txt"), "utf8"), "C");
        });
    });

    describe("Utils.assertPathSafe()", () => {
        it("rejects a path whose component below the root is a symlink", function () {
            linkDir(this, outside, path.join(target, "link"));
            const utils = new Utils();
            assert.throws(() => utils.assertPathSafe(target, path.join(target, "link")), IN_THE_WAY);
            assert.throws(() => utils.assertPathSafe(target, path.join(target, "link", "x", "y.txt")), IN_THE_WAY);
        });

        it("accepts the root itself, paths not on disk yet and paths outside the root", () => {
            const utils = new Utils();
            assert.doesNotThrow(() => utils.assertPathSafe(target, target));
            assert.doesNotThrow(() => utils.assertPathSafe(target, path.join(target, "missing", "file.txt")));
            assert.doesNotThrow(() => utils.assertPathSafe(target, path.join(outside, "file.txt")));
        });

        it("is a no-op for a custom fs without lstatSync", () => {
            const customFs = { statSync: fs.statSync, existsSync: fs.existsSync };
            const utils = new Utils({ fs: customFs });
            assert.strictEqual(utils.fs, customFs);
            assert.doesNotThrow(() => utils.assertPathSafe(target, path.join(target, "a.txt")));
        });
    });
});
