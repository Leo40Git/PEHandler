using PEHandler;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using static PEHandler.PEFile;
using static PEHandler.RsrcHandler;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace PEHandlerTest
{
    public partial class TestApp : Form
    {
        private PEFile peData;
        private RsrcHandler rsrcHandler;

        public TestApp()
        {
            InitializeComponent();
        }

        private void mFileLoadEXE_Click(object sender, EventArgs e)
        {
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                Stream s = openFileDialog.OpenFile();
                peData = new PEFile(s, 0x1000);
                s.Dispose();
                rsrcHandler = peData.RsrcHandler;
                ListBox.ObjectCollection items = sectionList.Items;
                items.Clear();
                foreach (Section sec in peData.Sections)
                {
                    items.Add(sec);
                }
                sectionList.SelectedIndex = 0;
                sectionList.Select();
            }
        }

        private void sectionList_SelectedIndexChanged(object sender, EventArgs e)
        {
            Control.ControlCollection controls = splitContainer.Panel2.Controls;
            controls.Clear();
            Section selSec = sectionList.SelectedItem as Section;
            int selSecID = peData.Sections.IndexOf(selSec);
            if (selSecID == peData.ResourcesIndex)
            {
                TreeView treeView = new TreeView
                {
                    Dock = DockStyle.Fill
                };
                TreeNodeCollection col = treeView.Nodes;
                AddNodes(rsrcHandler.Root, col);
                controls.Add(treeView);
            }
            else
            {
                FlowLayoutPanel panel = new FlowLayoutPanel();
                panel.FlowDirection = FlowDirection.TopDown;
                panel.Dock = DockStyle.Fill;
                controls.Add(panel);
                controls = panel.Controls;
                panelWidth = panel.Size.Width;
                AddLabel(controls, $"Tag: {selSec.Tag}");
                AddLabel(controls, $"Linearized: {(selSec.MetaLinearize ? "Yes" : "No")}");
                AddLabel(controls, $"Virtual Address: 0x{selSec.VirtualAddress.ToString("X8")}");
                AddLabel(controls, $"Virtual Size: 0x{selSec.VirtualSize.ToString("X8")}");
                AddLabel(controls, $"File Address: 0x{selSec.FileAddress.ToString("X8")}");
                AddLabel(controls, $"File Size: 0x{selSec.RawData.Length.ToString("X8")}");
                AddLabel(controls, $"Characteristics: {selSec.Characteristics}");
            }
        }

        private void AddNodes(RsrcEntry rootEntry, TreeNodeCollection col, TreeNode rootNode = null)
        {
            TreeNode entryNode = null;
            if (rootEntry.Parent != null)
            {
                entryNode = new TreeNode(rootEntry.PathName);
                if (rootNode == null)
                    col.Add(entryNode);
                else
                    rootNode.Nodes.Add(entryNode);
            }
            foreach (RsrcEntry entry in rootEntry.Entries)
            {
                if (entry.IsDirectory)
                    AddNodes(entry, col, entryNode);
                else
                    entryNode.Nodes.Add(entry.PathName);
            }
        }

        private int panelWidth;

        private void AddLabel(Control.ControlCollection controls, string Text)
        {
            Label lbl = new Label
            {
                Text = Text,
                Anchor = AnchorStyles.Top | AnchorStyles.Left,
                AutoSize = false
            };
            controls.Add(lbl);
            Size s = lbl.Size;
            s.Width = panelWidth;
            lbl.Size = s;
        }

        private void mFileSaveEXE_Click(object sender, EventArgs e)
        {
            if (saveFileDialog.ShowDialog(this) == DialogResult.OK)
            {
                byte[] data = peData.Write();
                Stream dst = saveFileDialog.OpenFile();
                dst.Write(data, 0, data.Length);
                dst.Dispose();
            }
        }
    }
}