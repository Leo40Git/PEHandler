using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PEHandler
{
    /// <summary>
    /// A generic PE EXE handling class.
    /// </summary>
    public class PEFile
    {
        /// <summary>
        /// The PE header.
        /// </summary>
        public readonly byte[] earlyHeader;

        /// <summary>
        /// Stream for the PE header.
        /// </summary>
        public readonly MemoryStream earlyHeaderMS;

        /// <summary>
        /// The complete list of sections.
        /// </summary>
        public List<Section> Sections { get; private set; }

        public PEFile(Stream src, uint expectedTex)
        {
            Sections = new List<Section>();
            src.Position = 0;
            earlyHeader = new byte[expectedTex];
            src.Read(earlyHeader, 0, (int)expectedTex);
            earlyHeaderMS = new MemoryStream(earlyHeader);
            earlyHeaderMS.Position = NtHeaders;
            if (earlyHeaderMS.ReadInt() != 0x00004550)
                throw new IOException("Not a valid PE file.");
            earlyHeaderMS.Position += 2; // short: machine
            uint sectionCount = (uint)(earlyHeaderMS.ReadShort() & 0xFFFF);
            earlyHeaderMS.Position += 8; // int 1: unknown, int 2: symtab address
            if (earlyHeaderMS.ReadInt() != 0)
                throw new IOException(
                    "This file was linked with a symbol table. Since we don't want to accidentally destroy it, you get this error instead.");
            uint optHeadSize = (uint)(earlyHeaderMS.ReadShort() & 0xFFFF);
            earlyHeaderMS.Position += 2; // short: characteristics
            // -- optional header --
            uint optHeadPoint = (uint)earlyHeaderMS.Position;
            if (optHeadSize < 0x78)
                throw new IOException("Optional header size is under 0x78 (RESOURCE table info)");
            ushort optHeadType = earlyHeaderMS.ReadShort();
            if (optHeadType != 0x010B)
                throw new IOException("Unknown optional header type: " + optHeadType.ToString("X"));
            // Check that size of headers is what we thought
            if (GetOptionalHeaderInt(0x3C) != expectedTex)
                throw new IOException("Size of headers must be as expected due to linearization fun");
            // Everything verified - load up the image sections
            src.Position = optHeadPoint + optHeadSize;
            for (uint i = 0; i < sectionCount; i++)
            {
                Section s = new Section();
                s.Read(src);
                Sections.Add(s);
            }
            Test(true);
        }

        private int Test(bool justOrderAndOverlap)
        {
            // You may be wondering: "Why so many passes?"
            // The answer: It simplifies the code.

            // -- Test virtual integrity
            Sections.OrderBy(x => x);
            // Sets the minimum RVA we can use. This works due to the virtual sorting stuff.
            uint rvaHeaderFloor = 0;
            foreach (Section s in Sections)
            {
                if (UCompare(s.VirtualAddrRelative) < UCompare(rvaHeaderFloor))
                    throw new IOException("Section RVA Overlap, " + s);
                rvaHeaderFloor = s.VirtualAddrRelative + s.VirtualSize;
            }
            if (justOrderAndOverlap)
                return -1;
            // -- Allocate file addresses
            uint sectionAlignment = GetOptionalHeaderInt(0x20);
            uint fileAlignment = GetOptionalHeaderInt(0x24);
            LinkedList<AllocationSpan> map = new LinkedList<AllocationSpan>();
            // Disallow collision with the primary header
            map.AddLast(new AllocationSpan(0, (uint)earlyHeader.Length));
            for (int i = 0; i < 2; i++)
            {
                foreach (Section s in Sections)
                {
                    if (s.MetaLinearize != (i == 0))
                        continue;
                    bool ok = false;
                    if (s.MetaLinearize)
                    {
                        ok = CheckAllocation(map, new AllocationSpan(s.VirtualAddrRelative, (uint)s.RawData.Length));
                        s.FileAddress = s.VirtualAddrRelative;
                    }
                    if (!ok)
                    {
                        uint position = 0;
                        while (!CheckAllocation(map, new AllocationSpan(position, (uint)s.RawData.Length)))
                            position += fileAlignment;
                        s.FileAddress = position;
                    }
                }
            }
            // -- Set Section Count / Rewrite section headers
            // 4: signature
            // 2: field: number of sections
            earlyHeaderMS.Position = NtHeaders + 4 + 2;
            earlyHeaderMS.WriteShort((ushort)Sections.Count);
            earlyHeaderMS.Position = SectionHeaders;
            foreach (Section s in Sections)
                s.WriteHead(earlyHeaderMS);
            // -- Image size is based on virtual size, not phys.
            uint imageSize = CalculateImageSize();
            SetOptionalHeaderInt(0x38, AlignForward(imageSize, sectionAlignment));
            // -- File size based on the allocation map
            uint fileSize = 0;
            foreach (AllocationSpan allocSpan in map)
            {
                uint v = allocSpan.start + allocSpan.length;
                if (UCompare(v) > UCompare(fileSize))
                    fileSize = v;
            }
            return (int)AlignForward(fileSize, fileAlignment);
        }

        private uint CalculateImageSize()
        {
            uint imageSize = 0;
            foreach (Section s in Sections)
            {
                uint v = s.VirtualAddrRelative + s.VirtualSize;
                if (UCompare(v) > UCompare(imageSize))
                    imageSize = v;
            }
            return imageSize;
        }

        private bool CheckAllocation(LinkedList<AllocationSpan> map, AllocationSpan newSpan)
        {
            foreach (AllocationSpan allocSpan in map)
                if (allocSpan.Collides(newSpan))
                    return false;
            map.AddLast(newSpan);
            return true;
        }

        public static uint AlignForward(uint virtualAddrRelative, uint fileAlignment)
        {
            uint mod = virtualAddrRelative % fileAlignment;
            if (mod != 0)
                virtualAddrRelative += fileAlignment - mod;
            return virtualAddrRelative;
        }

        public byte[] Write()
        {
            byte[] data = new byte[Test(false)];
            MemoryStream d = new MemoryStream(data);
            d.Write(earlyHeader, 0, earlyHeader.Length);
            foreach (Section s in Sections)
            {
                d.Position = s.FileAddress;
                d.Write(s.RawData, 0, s.RawData.Length);
            }
            d.Dispose();
            return data;
        }

        public uint NtHeaders
        {
            get
            {
                earlyHeaderMS.Position = 0x3C;
                return earlyHeaderMS.ReadInt();
            }
        }

        public uint SectionHeaders
        {
            get
            {
                uint nt = NtHeaders;
                // 4: Signature
                // 0x10: Field : Size of Optional Header
                earlyHeaderMS.Position = nt + 4 + 0x10;
                return (uint)(nt + 4 + 0x14 + (earlyHeaderMS.ReadShort() & 0xFFFF));
            }
        }

        private void SetOptHeaderIntPos(uint ofs)
        {
            // 0x18: Signature + IMAGE_FILE_HEADER
            earlyHeaderMS.Position = NtHeaders + 0x18 + ofs;
        }

        public uint GetOptionalHeaderInt(uint ofs)
        {
            SetOptHeaderIntPos(ofs);
            return earlyHeaderMS.ReadInt();
        }

        public void SetOptionalHeaderInt(uint ofs, uint v)
        {
            SetOptHeaderIntPos(ofs);
            byte[] numBuf = BitConverter.GetBytes(v);
            earlyHeaderMS.Write(numBuf, 0, numBuf.Length);
        }

        public MemoryStream SetupRVAPoint(uint rva)
        {
            foreach (Section s in Sections)
            {
                if (UCompare(rva) >= UCompare(s.VirtualAddrRelative))
                {
                    uint rel = rva - s.VirtualAddrRelative;
                    if (UCompare(rel) < Math.Max(UCompare((uint)s.RawData.Length), UCompare(s.VirtualSize)))
                    {
                        MemoryStream ms = new MemoryStream(s.RawData);
                        ms.Position = rel;
                        return ms;
                    }
                }
            }
            return null;
        }

        public int GetResourcesIndex()
        {
            int idx = 0;
            uint rsrcRVA = GetOptionalHeaderInt(0x70);
            foreach (Section s in Sections)
            {
                if (s.VirtualAddrRelative == rsrcRVA)
                    return idx;
                idx++;
            }
            return -1;
        }

        public int GetSectionIndexByTag(String tag)
        {
            int idx = 0;
            foreach (Section s in Sections)
            {
                if (s.Tag.Equals(tag))
                    return idx;
                idx++;
            }
            return -1;
        }

        public void Malloc(Section newS)
        {
            uint sectionAlignment = GetOptionalHeaderInt(0x20);
            Section rsrcSection = null;
            int rsI = GetResourcesIndex();
            if (rsI != -1)
            {
                rsrcSection = Sections.ElementAt(rsI);
                Sections.RemoveAt(rsI);
            }
            MallocInterior(newS, (uint)earlyHeader.Length, sectionAlignment);
            Sections.Add(newS);
            if (rsrcSection != null)
            {
                // rsrcSection has to be the latest section in the file
                uint oldResourcesRVA = rsrcSection.VirtualAddrRelative;
                MallocInterior(rsrcSection, CalculateImageSize(), sectionAlignment);
                uint newResourcesRVA = rsrcSection.VirtualAddrRelative;
                rsrcSection.ShiftResourceContents((int)(newResourcesRVA - oldResourcesRVA));
                Sections.Add(rsrcSection);
                SetOptionalHeaderInt(0x70, newResourcesRVA);
            }
        }

        private void MallocInterior(Section rsrcSection, uint i, uint sectionAlignment)
        {
            while (true)
            {
                i = AlignForward(i, sectionAlignment);
                // Is this OK?
                AllocationSpan allocSpan = new AllocationSpan(i, AlignForward(rsrcSection.VirtualSize, sectionAlignment));
                bool hit = false;
                foreach (Section s in Sections)
                {
                    if (new AllocationSpan(s.VirtualAddrRelative, AlignForward(s.VirtualSize, sectionAlignment))
                            .Collides(allocSpan))
                    {
                        hit = true;
                        break;
                    }
                }
                if (!hit)
                {
                    rsrcSection.VirtualAddrRelative = i;
                    return;
                }
                i += sectionAlignment;
            }
        }

        /// <summary>
        /// A PE section.
        /// </summary>
        public class Section : IComparable<Section>, IEquatable<Section>
        {
            [Flags]
            public enum SectionFlags : uint
            {
                /// <summary>
                /// Reserved for future use.
                /// </summary>
                RESERVED_000 = 0x00000000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                RESERVED_001 = 0x00000001,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                RESERVED_002 = 0x00000002,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                RESERVED_004 = 0x00000004,

                /// <summary>
                /// The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. This is valid only for object files.
                /// </summary>
                TYPE_NO_PAD = 0x00000008,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                RESERVED_010 = 0x00000010,

                /// <summary>
                /// The section contains executable code.
                /// </summary>
                CNT_CODE = 0x00000020,

                /// <summary>
                /// The section contains initialized data.
                /// </summary>
                CNT_INITIALIZED_DATA = 0x00000040,

                /// <summary>
                /// The section contains uninitialized data.
                /// </summary>
                CNT_UNINITIALIZED_DATA = 0x00000080,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                LNK_OTHER = 0x00000100,

                /// <summary>
                /// The section contains comments or other information. The .drectve section has this type. This is valid for object files only.
                /// </summary>
                LNK_INFO = 0x00000200,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                RESERVED_400 = 0x00000400,

                /// <summary>
                /// The section will not become part of the image. This is valid only for object files.
                /// </summary>
                LNK_REMOVE = 0x00000800,

                /// <summary>
                /// The section contains COMDAT data. For more information, see COMDAT Sections (Object Only). This is valid only for object files.
                /// </summary>
                LNK_COMDAT = 0x00001000,

                /// <summary>
                /// The section contains data referenced through the global pointer (GP).
                /// </summary>
                GPREL = 0x00008000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                MEM_PURGEABLE = 0x00020000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                MEM_16BIT = 0x00020000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                MEM_LOCKED = 0x00040000,

                /// <summary>
                /// Reserved for future use.
                /// </summary>
                MEM_PRELOAD = 0x00080000,

                /// <summary>
                /// Align data on a 1-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_1BYTES = 0x00100000,

                /// <summary>
                /// Align data on a 2-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_2BYTES = 0x00200000,

                /// <summary>
                /// Align data on a 4-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_4BYTES = 0x00300000,

                /// <summary>
                /// Align data on an 8-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_8BYTES = 0x00400000,

                /// <summary>
                /// Align data on a 16-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_16BYTES = 0x00500000,

                /// <summary>
                /// Align data on a 32-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_32BYTES = 0x00600000,

                /// <summary>
                /// Align data on a 64-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_64BYTES = 0x00700000,

                /// <summary>
                /// Align data on a 128-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_128BYTES = 0x00800000,

                /// <summary>
                /// Align data on a 256-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_256BYTES = 0x00900000,

                /// <summary>
                /// Align data on a 512-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_512BYTES = 0x00A00000,

                /// <summary>
                /// Align data on a 1024-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_1024BYTES = 0x00B00000,

                /// <summary>
                /// Align data on a 2048-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_2048BYTES = 0x00C00000,

                /// <summary>
                /// Align data on a 4096-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_4096BYTES = 0x00D00000,

                /// <summary>
                /// Align data on an 8192-byte boundary. Valid only for object files.
                /// </summary>
                ALIGN_8192BYTES = 0x00E00000,

                /// <summary>
                /// The section contains extended relocations.
                /// </summary>
                LNK_NRELOC_OVFL = 0x01000000,

                /// <summary>
                /// The section can be discarded as needed.
                /// </summary>
                MEM_DISCARDABLE = 0x02000000,

                /// <summary>
                /// The section cannot be cached.
                /// </summary>
                MEM_NOT_CACHED = 0x04000000,

                /// <summary>
                /// The section is not pageable.
                /// </summary>
                MEM_NOT_PAGED = 0x08000000,

                /// <summary>
                /// The section can be shared in memory.
                /// </summary>
                MEM_SHARED = 0x10000000,

                /// <summary>
                /// The section can be executed as code.
                /// </summary>
                MEM_EXECUTE = 0x20000000,

                /// <summary>
                /// The section can be read.
                /// </summary>
                MEM_READ = 0x40000000,

                /// <summary>
                /// The section can be written to.
                /// </summary>
                MEM_WRITE = 0x80000000,
            }

            private static readonly byte[] blankRawData = new byte[0];
            public bool MetaLinearize { get; set; }
            private byte[] tagData = new byte[8];

            public string Tag
            {
                get => Encoding.GetEncoding("Windows-1252").GetString(tagData);
                set
                {
                    if (value == null)
                        throw new ArgumentNullException("s");
                    byte[] data = Encoding.GetEncoding("Windows-1252").GetBytes(value);
                    Array.Copy(data, tagData, 8);
                }
            }

            public uint VirtualSize { get; set; }
            public uint VirtualAddrRelative { get; set; }
            public uint FileAddress { get; internal set; }
            public byte[] RawData { get; set; }
            public SectionFlags Characteristics { get; set; }

            public Section()
            {
                RawData = blankRawData;
                Characteristics = SectionFlags.CNT_INITIALIZED_DATA | SectionFlags.MEM_EXECUTE | SectionFlags.MEM_READ | SectionFlags.MEM_WRITE;
            }

            public void Read(Stream src)
            {
                src.Read(tagData, 0, 8);
                VirtualSize = src.ReadInt();
                VirtualAddrRelative = src.ReadInt();
                RawData = new byte[src.ReadInt()];
                FileAddress = src.ReadInt();
                MetaLinearize = FileAddress == VirtualAddrRelative;
                long saved = src.Position;
                src.Position = FileAddress;
                src.Read(RawData, 0, RawData.Length);
                src.Position = saved;
                src.Position += 8; // int 1: unknown, int 2: unknown
                if (src.ReadShort() != 0)
                    throw new IOException("Relocations not allowed");
                if (src.ReadShort() != 0)
                    throw new IOException("Line numbers not allowed");
                Characteristics = (SectionFlags)src.ReadInt();
            }

            public void WriteHead(MemoryStream earlyHeadMS)
            {
                earlyHeadMS.Write(tagData, 0, tagData.Length);
                earlyHeadMS.WriteInt(VirtualSize);
                earlyHeadMS.WriteInt(VirtualAddrRelative);
                earlyHeadMS.WriteInt((uint)RawData.Length);
                earlyHeadMS.WriteInt(FileAddress);
                earlyHeadMS.WriteInt(0);
                earlyHeadMS.WriteInt(0);
                earlyHeadMS.WriteShort(0);
                earlyHeadMS.WriteShort(0);
                earlyHeadMS.WriteInt((uint)Characteristics);
            }

            public override int GetHashCode()
            {
                var hashCode = 1956869319;
                hashCode = hashCode * -1521134295 + MetaLinearize.GetHashCode();
                hashCode = hashCode * -1521134295 + EqualityComparer<string>.Default.GetHashCode(Tag);
                hashCode = hashCode * -1521134295 + VirtualSize.GetHashCode();
                hashCode = hashCode * -1521134295 + VirtualAddrRelative.GetHashCode();
                hashCode = hashCode * -1521134295 + FileAddress.GetHashCode();
                hashCode = hashCode * -1521134295 + EqualityComparer<byte[]>.Default.GetHashCode(RawData);
                hashCode = hashCode * -1521134295 + Characteristics.GetHashCode();
                return hashCode;
            }

            public bool Equals(Section other)
            {
                return GetHashCode() == other.GetHashCode();
            }

            public int CompareTo(Section other)
            {
                if (VirtualAddrRelative < other.VirtualAddrRelative)
                    return -1;
                if (VirtualAddrRelative == other.VirtualAddrRelative)
                    return 0; // Impossible if they are different, but...
                return 1;
            }

            private void ShiftDirTable(MemoryStream ms, int amt, uint pointer)
            {
                ms.Position = pointer + 12;
                // get the # of rsrc subdirs indexed by name
                uint nEntry = ms.ReadShort();
                // get the # of rsrc subdirs indexed by id
                nEntry += ms.ReadShort();
                // read and shift entries
                uint pos = pointer + 16;
                for (uint i = 0; i < nEntry; i++)
                    RsrcShift(ms, amt, pos + i * 8);
            }

            private void RsrcShift(MemoryStream ms, int amt, uint pointer)
            {
                ms.Position = pointer + 4;
                uint rva = ms.ReadInt();
                if ((rva & 0x80000000) != 0) // if hi bit 1 points to another directory table
                    ShiftDirTable(ms, amt, rva & 0x7FFFFFFF);
                else
                {
                    ms.Position = rva;
                    uint oldVal = ms.ReadInt();
                    ms.Position = rva;
                    ms.WriteInt((uint)(oldVal + amt));
                }
            }

            public void ShiftResourceContents(int amt)
            {
                ShiftDirTable(new MemoryStream(RawData), amt, 0);
            }

            public override string ToString() => Tag;

            public string ToStringDetailed() => $"{Tag} : RVA {VirtualAddrRelative:X} : VS {VirtualSize:X} : RDS {RawData.Length} : CH {Characteristics}";
        }

        public static uint UCompare(uint a)
        {
            // 0xFFFFFFFF (-1) becomes 0x7FFFFFFF (highest number)
            // 0x00000000 (0) becomes 0x80000000 (lowest number)
            return a ^ 0x80000000;
        }

        private class AllocationSpan
        {
            public uint start, length;

            public AllocationSpan(uint fa, uint size)
            {
                start = fa;
                length = size;
            }

            public bool Collides(AllocationSpan other)
            {
                return Within(other.start) || Within(other.start + other.length - 1) || other.Within(start)
                        || other.Within(start + length - 1);
            }

            private bool Within(uint target)
            {
                return (UCompare(target) >= UCompare(start)) && (UCompare(start + length) > UCompare(target));
            }
        }
    }
}