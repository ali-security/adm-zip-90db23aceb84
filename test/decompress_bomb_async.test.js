"use strict";

const { expect } = require("chai");
const fs = require("fs");
const pth = require("path");
const zlib = require("zlib");
const rimraf = require("rimraf");
const Zip = require("../adm-zip");
const Utils = require("../util");

// Regression test for GHSA-c6fg-446q-cg94:
// the synchronous getData() path caps inflation at the entry's declared
// uncompressed size (zlib maxOutputLength), but the asynchronous path streams
// through zlib.createInflateRaw(), which ignores maxOutputLength. A small archive
// declaring a tiny size could therefore inflate to an arbitrary amount of memory
// through getDataAsync() and every API built on it (readFileAsync,
// readAsTextAsync, extractAllToAsync). The async path must enforce the same cap.

const NODE_MAJOR = +process.versions.node.split(".")[0] || 0;

const u16 = (n) => {
    const b = Buffer.alloc(2);
    b.writeUInt16LE(n >>> 0);
    return b;
};
const u32 = (n) => {
    const b = Buffer.alloc(4);
    b.writeUInt32LE(n >>> 0);
    return b;
};

// Build a single-entry zip whose local and central headers declare
// `declaredSize` uncompressed bytes. `crc` is the CRC-32 of the real content, so
// an over-long entry is only caught by the output cap, never by the CRC check.
function craftZip(name, method, compressed, declaredSize, crc) {
    const fileName = Buffer.from(name);
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(compressed.length),
        u32(declaredSize),
        u16(fileName.length),
        u16(0),
        fileName,
        compressed
    ]);
    const cd = Buffer.concat([
        u32(0x02014b50),
        u16(20),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(compressed.length),
        u32(declaredSize),
        u16(fileName.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        fileName
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

// A deflated entry carrying `content` but declaring `declaredSize` bytes.
function deflatedZip(content, declaredSize) {
    return craftZip("bomb.bin", 8 /* DEFLATED */, zlib.deflateRawSync(content), declaredSize, Utils.crc32(content));
}

// Calls `read(cb)` and reports the first callback's arguments together with the
// total number of callbacks, after a short grace period during which a late
// "data"/"end"/"error" event from an aborted stream would show up as a second
// callback.
function firstResult(read, cb) {
    let calls = 0;
    read(function () {
        calls++;
        if (calls === 1) {
            const args = Array.prototype.slice.call(arguments);
            setTimeout(() => cb(args, calls), 50);
        }
    });
}

const CAP_ERROR = /exceeds the declared uncompressed size/;

describe("decompression bomb (async output cap) - GHSA-c6fg-446q-cg94", () => {
    // 4 MiB of a repeated byte deflates to a few KB, so the declared size is the
    // only thing standing between a tiny archive and a large allocation.
    const PAYLOAD = Buffer.alloc(4 * 1024 * 1024, 0x41);
    const BOMB = deflatedZip(PAYLOAD, 1);
    const ZERO_SIZE_BOMB = deflatedZip(PAYLOAD, 0);
    const destination = pth.join(__dirname, "xxx_async_cap");

    afterEach((done) => rimraf(destination, done));

    it("getData rejects an entry that inflates past its declared size (sync guard, Node >= 15)", function () {
        if (NODE_MAJOR < 15) this.skip(); // zlib maxOutputLength only exists on Node >= 15
        const zip = new Zip(BOMB);
        expect(() => zip.getEntries()[0].getData()).to.throw();
    });

    it("getDataAsync rejects an entry that inflates past its declared size", (done) => {
        const zip = new Zip(BOMB);
        firstResult(
            (cb) => zip.getEntries()[0].getDataAsync(cb),
            (args, calls) => {
                try {
                    const data = args[0];
                    const err = args[1];
                    expect(String(err)).to.match(CAP_ERROR);
                    expect(data.length, "no inflated data may be returned").to.equal(0);
                    expect(calls, "callback must fire exactly once").to.equal(1);
                    done();
                } catch (e) {
                    done(e);
                }
            }
        );
    });

    it("getDataAsync rejects an entry inflating one byte past its declared size", (done) => {
        const content = Buffer.from("boundary check ".repeat(4000));
        const zip = new Zip(deflatedZip(content, content.length - 1));
        zip.getEntries()[0].getDataAsync((data, err) => {
            try {
                expect(String(err)).to.match(CAP_ERROR);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("readFileAsync rejects an entry that inflates past its declared size", (done) => {
        const zip = new Zip(BOMB);
        zip.readFileAsync("bomb.bin", (data, err) => {
            try {
                expect(String(err)).to.match(CAP_ERROR);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("readAsTextAsync rejects an entry that inflates past its declared size", (done) => {
        const zip = new Zip(BOMB);
        zip.readAsTextAsync("bomb.bin", (data, err) => {
            try {
                expect(String(err)).to.match(CAP_ERROR);
                expect(data.length).to.equal(0);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    it("extractAllToAsync rejects an entry that inflates past its declared size", (done) => {
        const zip = new Zip(BOMB);
        zip.extractAllToAsync(destination, true, false, (err) => {
            try {
                expect(String(err)).to.match(CAP_ERROR);
                expect(fs.existsSync(pth.join(destination, "bomb.bin")), "the oversized entry must not be written").to.equal(false);
                done();
            } catch (e) {
                done(e);
            }
        });
    });

    describe("a declared size of 0 does not disable the cap", () => {
        it("getDataAsync rejects a non-empty entry declaring size 0", (done) => {
            const zip = new Zip(ZERO_SIZE_BOMB);
            zip.getEntries()[0].getDataAsync((data, err) => {
                try {
                    expect(String(err)).to.match(CAP_ERROR);
                    expect(data.length).to.equal(0);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });

        it("getData rejects a non-empty entry declaring size 0 (Node >= 15)", function () {
            if (NODE_MAJOR < 15) this.skip(); // zlib maxOutputLength only exists on Node >= 15
            const zip = new Zip(ZERO_SIZE_BOMB);
            expect(() => zip.getEntries()[0].getData()).to.throw();
        });

        it("still reads a genuinely empty deflated entry", (done) => {
            const empty = Buffer.alloc(0);
            const zip = new Zip(deflatedZip(empty, 0));
            expect(zip.getEntries()[0].getData().length).to.equal(0);
            zip.getEntries()[0].getDataAsync((data, err) => {
                try {
                    expect(err).to.equal(undefined);
                    expect(data.length).to.equal(0);
                    done();
                } catch (e) {
                    done(e);
                }
            });
        });
    });

    describe("legitimate entries are unaffected", () => {
        // larger than zlib's 16 KiB chunk size, so it arrives in many "data" events
        const content = Buffer.from(Array.from({ length: 20000 }, (_, i) => "line " + i + "\n").join(""));

        it("getDataAsync returns an entry inflating to exactly its declared size", (done) => {
            const zip = new Zip(deflatedZip(content, content.length));
            firstResult(
                (cb) => zip.getEntries()[0].getDataAsync(cb),
                (args, calls) => {
                    try {
                        expect(args[1]).to.equal(undefined);
                        expect(args[0].equals(content)).to.equal(true);
                        expect(calls).to.equal(1);
                        done();
                    } catch (e) {
                        done(e);
                    }
                }
            );
        });

        it("readAsTextAsync and extractAllToAsync round-trip a regular archive", (done) => {
            const src = new Zip();
            src.addFile("d.txt", content);
            const zip = new Zip(src.toBuffer());
            zip.readAsTextAsync("d.txt", (text, err) => {
                try {
                    expect(err).to.equal(undefined);
                    expect(text).to.equal(content.toString("utf8"));
                } catch (e) {
                    return done(e);
                }
                zip.extractAllToAsync(destination, true, false, (err2) => {
                    try {
                        expect(err2).to.equal(undefined);
                        expect(fs.readFileSync(pth.join(destination, "d.txt")).equals(content)).to.equal(true);
                        done();
                    } catch (e) {
                        done(e);
                    }
                });
            });
        });
    });
});
