using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static PEHandler.PEFile;

namespace PEHandler
{
    public class RsrcHandler
    {
        public class RsrcEntry
        {
            public RsrcEntry Parent { get; internal set; }
            private RsrcEntry cachedParent;
            private RsrcEntry cachedTopParent;

            public RsrcEntry TopParent
            {
                get
                {
                    if (cachedTopParent == null || cachedParent != Parent)
                    {
                        cachedParent = Parent;
                        cachedTopParent = Parent;
                        while (cachedTopParent.Parent != null && cachedTopParent.Parent.Parent != null)
                            cachedTopParent = cachedTopParent.Parent;
                    }
                    return cachedTopParent;
                }
            }

            public string Name { get; set; }
            public uint ID { get; set; }

            public string PathName => Name ?? ID.ToString();

            public override string ToString() => PathName;

            public byte[] Data { get; set; }
            public List<RsrcEntry> Entries { get; set; }
            public uint DataCodepage { get; set; }
            public uint DataReserved { get; set; }
            public uint DirCharacteristics { get; set; }
            public uint DirTimestamp { get; set; }
            public ushort DirVersionMajor { get; set; }
            public ushort DirVersionMinor { get; set; }

            internal RsrcEntry(RsrcEntry parent)
            {
                Parent = parent;
            }

            public string ToPath()
            {
                string path = "";
                RsrcEntry entry = this;
                while (entry.Parent != null && entry.Parent.Parent != null)
                {
                    path = entry.PathName + "/" + path;
                    entry = entry.Parent;
                }
                return path;
            }

            public bool IsDirectory() => Entries != null;

            private void AssertIsDirectory()
            {
                if (!IsDirectory())
                    throw new InvalidOperationException("This method can't be invoked using a non-directory entry!");
            }

            private RsrcEntry AddSubEntry()
            {
                AssertIsDirectory();
                RsrcEntry e = new RsrcEntry(this);
                Entries.Add(e);
                return e;
            }

            public RsrcEntry AddSubEntry(string name)
            {
                RsrcEntry e = AddSubEntry();
                e.Name = name ?? throw new ArgumentNullException("name");
                return e;
            }

            public RsrcEntry AddSubEntry(uint id)
            {
                RsrcEntry e = AddSubEntry();
                e.ID = id;
                return e;
            }

            public RsrcEntry GetSubEntry(string name)
            {
                if (name == null)
                    throw new ArgumentNullException("name");
                AssertIsDirectory();
                foreach (RsrcEntry entry in Entries)
                {
                    if (name.Equals(entry.Name))
                        return entry;
                }
                return null;
            }

            public bool HasSubEntry(string name)
            {
                return GetSubEntry(name) != null;
            }

            public RsrcEntry GetSubEntry(uint id)
            {
                AssertIsDirectory();
                foreach (RsrcEntry entry in Entries)
                {
                    if (entry.Name != null)
                        continue;
                    if (id == entry.ID)
                        return entry;
                }
                return null;
            }

            public bool HasSubEntry(uint id)
            {
                return GetSubEntry(id) != null;
            }
        }

        public RsrcEntry Root { get; private set; }

        public RsrcEntry AddEntry(string name)
        {
            return Root.AddSubEntry(name);
        }

        public RsrcEntry AddEntry(uint id)
        {
            return Root.AddSubEntry(id);
        }

        public RsrcEntry GetEntry(string name)
        {
            return Root.GetSubEntry(name);
        }

        public bool HasEntry(string name)
        {
            return Root.HasSubEntry(name);
        }

        public RsrcEntry GetEntry(uint id)
        {
            return Root.GetSubEntry(id);
        }

        public bool HasEntry(uint id)
        {
            return Root.HasSubEntry(id);
        }

        public RsrcEntry GetEntryFromPath(String path)
        {
            path = path.Trim();
            if (path.Length == 0)
                return Root;
            RsrcEntry entry = Root;
            string[] pathParts = path.Split('/');
            string donePath = "";
            for (int i = 0; i < pathParts.Length; i++)
            {
                string pathPart = pathParts[i];
                donePath += pathPart + "/";
                if (entry.HasSubEntry(pathPart))
                    entry = entry.GetSubEntry(pathPart);
                else
                {
                    uint id = 0;
                    bool ok = uint.TryParse(pathPart, out id);
                    if (ok)
                        entry = entry.GetSubEntry(id);
                    else
                        throw new Exception("Could not find entry: " + donePath.Substring(0, donePath.Length - 1));
                }
                if (i != pathParts.Length - 1 && !entry.IsDirectory())
                    throw new Exception("Entry isn't a directory: " + donePath.Substring(0, donePath.Length - 1));
            }
            return entry;
        }

        public RsrcHandler(PEFile srcFile)
        {
            int rsI = srcFile.GetResourcesIndex();
            if (rsI < 0)
                throw new ArgumentException("srcFile does not have a .rsrc section!");
            Section rsrcSec = srcFile.Sections.ElementAt(rsI);
            rsrcSec.ShiftResourceContents((int)-rsrcSec.VirtualAddrRelative);
            Root = new RsrcEntry(null)
            {
                Entries = new List<RsrcEntry>()
            };
            MemoryStream src = new MemoryStream(rsrcSec.RawData);
            ReadDirectory(src, Root);
            src.Dispose();
            rsrcSec.ShiftResourceContents((int)rsrcSec.VirtualAddrRelative);
        }

        public void Write(PEFile dstFile)
        {
            int rsI = dstFile.GetResourcesIndex();
            if (rsI < 0)
                throw new ArgumentException("srcFile does not have a .rsrc section!");
            Section rsrcSec = dstFile.Sections.ElementAt(rsI);
            dstFile.Sections.RemoveAt(rsI);
            // 0th romp to calculate section sizes
            SectionSizes sectionSizes = CalculateSectionSizes(Root);
            byte[] dstBuf = new byte[sectionSizes.totalSize];
            MemoryStream dst = new MemoryStream(dstBuf);
            ReferenceMemory refMem = new ReferenceMemory();
            // write directories, leave references blank
            WriteDirectory(dst, Root, refMem);
            // write references
            WriteReferences(dst, sectionSizes, refMem);
            rsrcSec.RawData = dstBuf;
            rsrcSec.VirtualSize = (uint)dstBuf.Length;
            dstFile.Malloc(rsrcSec);
            uint rsrcSecRVA = rsrcSec.VirtualAddrRelative;
            rsrcSec.ShiftResourceContents((int)rsrcSecRVA);
            dstFile.SetOptionalHeaderInt(0x70, rsrcSecRVA);
        }

        private void ReadDirectory(MemoryStream src, RsrcEntry root)
        {
            long posStorage = 0;
            root.DirCharacteristics = src.ReadInt();
            root.DirTimestamp = src.ReadInt();
            root.DirVersionMajor = src.ReadShort();
            root.DirVersionMinor = src.ReadShort();
            uint entries = src.ReadShort();
            entries += src.ReadShort();
            for (uint i = 0; i < entries; i++)
            {
                RsrcEntry entry = new RsrcEntry(root);
                uint nameOffset = src.ReadInt();
                if ((nameOffset & 0x80000000) == 0)
                    // id
                    entry.ID = nameOffset;
                else
                {
                    // name
                    posStorage = src.Position;
                    nameOffset &= 0x7FFFFFFF;
                    src.Position = nameOffset;
                    ushort nameLen = src.ReadShort();
                    char[] nameBuf = new char[nameLen];
                    for (int j = 0; j < nameLen; j++)
                        nameBuf[j] = (char)src.ReadShort();
                    entry.Name = new string(nameBuf);
                    src.Position = posStorage;
                }
                ReadEntryData(src, entry);
                root.Entries.Add(entry);
            }
        }

        private void ReadEntryData(MemoryStream src, RsrcEntry entry)
        {
            uint dataOffset = src.ReadInt();
            long posStorage = src.Position;
            if ((dataOffset & 0x80000000) == 0)
            {
                // data
                src.Position = dataOffset;
                uint dataPos = src.ReadInt();
                uint dataSize = src.ReadInt();
                entry.DataCodepage = src.ReadInt();
                entry.DataReserved = src.ReadInt();
                // read the data
                src.Position = dataPos;
                byte[] entryData = new byte[dataSize];
                src.Read(entryData, 0, (int)dataSize);
                entry.Data = entryData;
            }
            else
            {
                // subdirectory
                dataOffset &= 0x7FFFFFFF;
                entry.Entries = new List<RsrcEntry>();
                src.Position = dataOffset;
                ReadDirectory(src, entry);
            }
            src.Position = posStorage;
        }

        private struct SectionSizes
        {
            public uint totalSize;
            public uint directorySize;
            public uint dataEntrySize;
            public uint stringSize;
            public uint dataSize;

            public static SectionSizes operator +(SectionSizes s1, SectionSizes s2)
            {
                SectionSizes sizes;
                sizes.directorySize = s1.directorySize + s2.directorySize;
                sizes.dataEntrySize = s1.totalSize + s2.dataEntrySize;
                sizes.stringSize = s1.totalSize + s2.stringSize;
                sizes.dataSize = s1.totalSize + s2.dataSize;
                sizes.totalSize = sizes.directorySize + sizes.dataEntrySize + sizes.stringSize + sizes.dataSize;
                return sizes;
            }
        }

        private SectionSizes CalculateSectionSizes(RsrcEntry root, List<string> allocStr = null)
        {
            if (allocStr == null)
                allocStr = new List<string>();
            SectionSizes sizes;
            sizes.totalSize = 0;
            sizes.directorySize = 0x10;
            sizes.dataEntrySize = 0;
            sizes.stringSize = 0;
            sizes.dataSize = 0;
            foreach (RsrcEntry entry in root.Entries)
            {
                sizes.directorySize += 8;
                if (entry.Name != null && !allocStr.Contains(entry.Name))
                {
                    allocStr.Add(entry.Name);
                    sizes.stringSize += 2 + (uint)entry.Name.Length * 2;
                }
                if (entry.Data != null)
                {
                    sizes.dataEntrySize += 0x10;
                    sizes.dataSize += (uint)entry.Data.Length;
                }
                else if (entry.IsDirectory())
                    sizes += CalculateSectionSizes(root, allocStr);
                else
                    throw new Exception("Entry has no data nor any subentries: " + entry.ToPath());
            }
            sizes.totalSize = sizes.directorySize + sizes.dataEntrySize + sizes.stringSize + sizes.dataSize;
            return sizes;
        }

        private class ReferenceMemory
        {
            public Dictionary<RsrcEntry, uint> directoryOffsets;
            public Dictionary<RsrcEntry, List<uint>> directoryReferences;
            public Dictionary<RsrcEntry, List<uint>> dataEntryReferences;
            public Dictionary<string, List<uint>> stringReferences;

            public ReferenceMemory()
            {
                directoryOffsets = new Dictionary<RsrcEntry, uint>();
                directoryReferences = new Dictionary<RsrcEntry, List<uint>>();
                dataEntryReferences = new Dictionary<RsrcEntry, List<uint>>();
                stringReferences = new Dictionary<string, List<uint>>();
            }

            public void AddDirectoryOffset(RsrcEntry entry, uint offPos)
            {
                directoryOffsets.Add(entry, offPos);
            }

            private void AddReference<TKey>(Dictionary<TKey, List<uint>> refMap, TKey key, uint refPos)
            {
                List<uint> refList = null;
                bool succ = refMap.TryGetValue(key, out refList);
                if (!succ)
                {
                    refList = new List<uint>();
                    refMap.Add(key, refList);
                }
                refList.Add(refPos);
            }

            public void AddDirectoryReference(RsrcEntry entry, uint refPos)
            {
                AddReference(directoryReferences, entry, refPos);
            }

            public void AddDataEntryReference(RsrcEntry entry, uint refPos)
            {
                AddReference(dataEntryReferences, entry, refPos);
            }

            public void AddStringReference(string str, uint refPos)
            {
                AddReference(stringReferences, str, refPos);
            }
        }

        private void WriteDirectory(MemoryStream dst, RsrcEntry root, ReferenceMemory refMem)
        {
            refMem.AddDirectoryOffset(root, (uint)dst.Position);
            // write unimportant fields
            dst.WriteInt(root.DirCharacteristics);
            dst.WriteInt(root.DirTimestamp);
            dst.WriteShort(root.DirVersionMajor);
            dst.WriteShort(root.DirVersionMinor);
            // first romp to count name/ID entries
            List<RsrcEntry> nameEntries = new List<RsrcEntry>(), idEntries = new List<RsrcEntry>();
            ushort nameEntryCount = 0, idEntryCount = 0;
            foreach (RsrcEntry entry in root.Entries)
            {
                if (entry.Name == null)
                {
                    nameEntryCount++;
                    idEntries.Add(entry);
                }
                else
                {
                    idEntryCount++;
                    nameEntries.Add(entry);
                }
            }
            List<RsrcEntry> entries = new List<RsrcEntry>(nameEntries);
            entries.AddRange(idEntries);
            // write em out
            dst.WriteShort(nameEntryCount);
            dst.WriteShort(idEntryCount);
            // second romp to actually write it
            // make a subdir list to write *after* writing the entire directory
            List<RsrcEntry> subdirs = new List<RsrcEntry>();
            foreach (RsrcEntry entry in entries)
            {
                if (entry.Name == null)
                    dst.WriteInt(entry.ID);
                else
                {
                    refMem.AddStringReference(entry.Name, (uint)dst.Position);
                    dst.WriteInt(0x80000000);
                }
                if (entry.IsDirectory())
                {
                    refMem.AddDirectoryReference(entry, (uint)dst.Position);
                    dst.WriteInt(0x80000000);
                    subdirs.Add(entry);
                }
                else if (entry.Data != null)
                {
                    refMem.AddDataEntryReference(entry, (uint)dst.Position);
                    dst.WriteInt(0);
                }
                else
                    throw new Exception("Entry has no data nor any subentries: " + entry.ToPath());
            }
            // now write the subdirectories
            foreach (RsrcEntry entry in subdirs)
                WriteDirectory(dst, entry, refMem);
        }

        private void WriteReferences(MemoryStream dst, SectionSizes sectionSizes, ReferenceMemory refMem)
        {
            // write subdirectory references
            foreach (KeyValuePair<RsrcEntry, List<uint>> entry in refMem.directoryReferences)
            {
                bool ok = refMem.directoryOffsets.TryGetValue(entry.Key, out uint off);
                if (!ok)
                    throw new Exception("Directory is missing offset: " + entry.Key.ToPath());
                off |= 0x80000000;
                foreach (uint refLoc in entry.Value)
                {
                    dst.Position = refLoc;
                    dst.WriteInt(off);
                }
            }
            // write actual data, remember offsets
            Dictionary<RsrcEntry, uint> dataOffsets = new Dictionary<RsrcEntry, uint>();
            dst.Position = sectionSizes.directorySize + sectionSizes.dataEntrySize + sectionSizes.stringSize;
            foreach (KeyValuePair<RsrcEntry, List<uint>> entry in refMem.dataEntryReferences)
            {
                dataOffsets.Add(entry.Key, (uint)dst.Position);
                byte[] data = entry.Key.Data;
                dst.Write(data, 0, data.Length);
            }
            // write data entries and their references
            dst.Position = sectionSizes.directorySize;
            foreach (KeyValuePair<RsrcEntry, List<uint>> entry in refMem.dataEntryReferences)
            {
                uint off = (uint)dst.Position;
                foreach (uint refLoc in entry.Value)
                {
                    dst.Position = refLoc;
                    dst.WriteInt(off);
                }
                dst.Position = off;
                RsrcEntry rsrc = entry.Key;
                bool ok = dataOffsets.TryGetValue(rsrc, out uint dataPos);
                if (!ok)
                    throw new Exception("Data is missing offset: " + rsrc.ToPath());
                dst.WriteInt(dataPos);
                dst.WriteInt((uint)rsrc.Data.Length);
                dst.WriteInt(rsrc.DataCodepage);
                dst.WriteInt(rsrc.DataReserved);
            }
            // write strings (directory names) and their references
            dst.Position = sectionSizes.directorySize + sectionSizes.dataEntrySize;
            foreach (KeyValuePair<string, List<uint>> entry in refMem.stringReferences)
            {
                uint pos = (uint)dst.Position;
                uint off = pos | 0x80000000;
                foreach (uint refLoc in entry.Value)
                {
                    dst.Position = refLoc;
                    dst.WriteInt(off);
                }
                dst.Position = pos;
                string str = entry.Key;
                ushort strLen = (ushort)str.Length;
                dst.WriteShort(strLen);
                for (int i = 0; i < strLen; i++)
                    dst.WriteShort(str[i]);
            }
        }
    }
}