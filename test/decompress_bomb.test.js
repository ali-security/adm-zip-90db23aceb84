"use strict";

const { expect } = require("chai");
const Zip = require("../adm-zip");
const zlib = require("zlib");

// Regression test for CVE-2026-39244:
// adm-zip allocated the entry output buffer from the attacker-declared
// uncompressed size (central-directory / local-header size field) before any
// validation. A tiny crafted archive could declare a ~4 GB size and force a
// matching Buffer.alloc, OOM-killing the process. The allocation must be bound
// by the data actually present in the archive, not by the declared size.

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

// Build a single-entry zip that declares `declaredSize` uncompressed bytes while
// only carrying `content` bytes of (crc-invalid) payload.
function craftBomb(declaredSize, method, content) {
    const name = Buffer.from("a");
    const crc = 0; // deliberately wrong: alloc used to happen before the crc check
    const lfh = Buffer.concat([
        u32(0x04034b50),
        u16(20),
        u16(0),
        u16(method),
        u16(0),
        u16(0),
        u32(crc),
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        name,
        content
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
        u32(content.length),
        u32(declaredSize),
        u16(name.length),
        u16(0),
        u16(0),
        u16(0),
        u16(0),
        u32(0),
        u32(0),
        name
    ]);
    const eocd = Buffer.concat([u32(0x06054b50), u16(0), u16(0), u16(1), u16(1), u32(cd.length), u32(lfh.length), u16(0)]);
    return Buffer.concat([lfh, cd, eocd]);
}

// Runs `fn` and returns the largest size it requested from Buffer.alloc. Requests
// above `limit` are refused instead of being served, so a regression is reported
// deterministically (and quickly) regardless of how the OS backs the memory.
function largestAllocation(fn, limit) {
    const realAlloc = Buffer.alloc;
    let largest = 0;
    Buffer.alloc = function (size) {
        if (size > largest) largest = size;
        if (size > limit) throw new RangeError("refused Buffer.alloc(" + size + ")");
        return realAlloc.apply(Buffer, arguments);
    };
    try {
        fn();
    } catch (e) {
        // the crafted archives are invalid; only the requested sizes matter here
    } finally {
        Buffer.alloc = realAlloc;
    }
    return largest;
}

describe("decompression bomb (declared size) - CVE-2026-39244", () => {
    const DECLARED = 3 * 1024 * 1024 * 1024; // ~3 GB, far above any plausible RSS budget

    it("does not allocate the declared size for a STORED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
        const before = process.memoryUsage().rss;
        // invalid crc -> must throw, but crucially without committing gigabytes
        expect(() => zip.getEntries()[0].getData()).to.throw(/CRC32/);
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("does not allocate the declared size for a DEFLATED entry", () => {
        const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
        const before = process.memoryUsage().rss;
        // bogus deflate stream / crc -> must throw without a huge eager allocation
        expect(() => zip.getEntries()[0].getData()).to.throw();
        const grewMB = (process.memoryUsage().rss - before) / (1024 * 1024);
        expect(grewMB, "RSS growth must stay bounded by real data, not declared size").to.be.below(256);
    });

    it("still reads a legitimate STORED entry", () => {
        const zip = new Zip();
        zip.addFile("s.bin", Buffer.from([1, 2, 3, 4, 5]));
        const round = new Zip(zip.toBuffer());
        expect([...round.readFile("s.bin")]).to.eql([1, 2, 3, 4, 5]);
    });

    it("still reads a legitimate DEFLATED entry", () => {
        const zip = new Zip();
        const payload = Buffer.from("hello world ".repeat(5000));
        zip.addFile("d.txt", payload);
        const round = new Zip(zip.toBuffer());
        expect(round.readFile("d.txt").equals(payload)).to.equal(true);
    });

    describe("Buffer.alloc stays bounded by the data present in the archive", () => {
        const LIMIT = 1024 * 1024; // the crafted archives carry only a few bytes of payload
        const deflated = zlib.deflateRawSync(Buffer.from("hello"));

        it("getData on a STORED entry", () => {
            const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
            expect(largestAllocation(() => zip.getEntries()[0].getData(), LIMIT)).to.be.at.most(LIMIT);
        });

        it("getData on a DEFLATED entry with a bogus stream", () => {
            const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, Buffer.from([0x00])));
            expect(largestAllocation(() => zip.getEntries()[0].getData(), LIMIT)).to.be.at.most(LIMIT);
        });

        it("getData on a DEFLATED entry with a valid stream", () => {
            const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, deflated));
            expect(largestAllocation(() => zip.getEntries()[0].getData(), LIMIT)).to.be.at.most(LIMIT);
        });

        it("readFile, readAsText and test on a STORED entry", () => {
            const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
            expect(largestAllocation(() => zip.readFile("a"), LIMIT)).to.be.at.most(LIMIT);
            expect(largestAllocation(() => zip.readAsText("a"), LIMIT)).to.be.at.most(LIMIT);
            let tested;
            expect(largestAllocation(() => (tested = zip.test()), LIMIT)).to.be.at.most(LIMIT);
            expect(tested).to.equal(false);
        });

        it("getDataAsync on a STORED entry", () => {
            const zip = new Zip(craftBomb(DECLARED, 0 /* STORED */, Buffer.from("A")));
            let result = null;
            const largest = largestAllocation(
                () =>
                    zip.getEntries()[0].getDataAsync((data, err) => {
                        result = { data, err };
                    }),
                LIMIT
            );
            expect(largest).to.be.at.most(LIMIT);
            expect(result).to.not.equal(null);
            expect(String(result.err)).to.match(/CRC32/);
            // the output is sized from the real payload, not from the declared size
            expect(result.data.length).to.equal(1);
        });

        it("getDataAsync on a DEFLATED entry", (done) => {
            const zip = new Zip(craftBomb(DECLARED, 8 /* DEFLATED */, deflated));
            const largest = largestAllocation(
                () =>
                    zip.getEntries()[0].getDataAsync((data, err) => {
                        try {
                            expect(String(err)).to.match(/CRC32/);
                            expect(data.length).to.equal(5);
                            done();
                        } catch (e) {
                            done(e);
                        }
                    }),
                LIMIT
            );
            try {
                expect(largest).to.be.at.most(LIMIT);
            } catch (e) {
                done(e);
            }
        });
    });
});
