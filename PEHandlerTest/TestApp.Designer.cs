namespace PEHandlerTest
{
    partial class TestApp
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.openFileDialog = new System.Windows.Forms.OpenFileDialog();
            this.menuStrip = new System.Windows.Forms.MenuStrip();
            this.mFile = new System.Windows.Forms.ToolStripMenuItem();
            this.mFileLoadEXE = new System.Windows.Forms.ToolStripMenuItem();
            this.mFileSaveEXE = new System.Windows.Forms.ToolStripMenuItem();
            this.splitContainer = new System.Windows.Forms.SplitContainer();
            this.sectionList = new System.Windows.Forms.ListBox();
            this.saveFileDialog = new System.Windows.Forms.SaveFileDialog();
            this.menuStrip.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer)).BeginInit();
            this.splitContainer.Panel1.SuspendLayout();
            this.splitContainer.SuspendLayout();
            this.SuspendLayout();
            // 
            // openFileDialog
            // 
            this.openFileDialog.DefaultExt = "exe";
            this.openFileDialog.Filter = "EXE files|*.exe";
            // 
            // menuStrip
            // 
            this.menuStrip.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mFile});
            this.menuStrip.Location = new System.Drawing.Point(0, 0);
            this.menuStrip.Name = "menuStrip";
            this.menuStrip.Size = new System.Drawing.Size(800, 24);
            this.menuStrip.TabIndex = 0;
            this.menuStrip.Text = "menuStrip";
            // 
            // mFile
            // 
            this.mFile.DropDownItems.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.mFileLoadEXE,
            this.mFileSaveEXE});
            this.mFile.Name = "mFile";
            this.mFile.Size = new System.Drawing.Size(37, 20);
            this.mFile.Text = "File";
            // 
            // mFileLoadEXE
            // 
            this.mFileLoadEXE.Name = "mFileLoadEXE";
            this.mFileLoadEXE.Size = new System.Drawing.Size(180, 22);
            this.mFileLoadEXE.Text = "Load EXE";
            this.mFileLoadEXE.Click += new System.EventHandler(this.mFileLoadEXE_Click);
            // 
            // mFileSaveEXE
            // 
            this.mFileSaveEXE.Name = "mFileSaveEXE";
            this.mFileSaveEXE.Size = new System.Drawing.Size(180, 22);
            this.mFileSaveEXE.Text = "Save EXE";
            this.mFileSaveEXE.Click += new System.EventHandler(this.mFileSaveEXE_Click);
            // 
            // splitContainer
            // 
            this.splitContainer.Dock = System.Windows.Forms.DockStyle.Fill;
            this.splitContainer.Location = new System.Drawing.Point(0, 24);
            this.splitContainer.Name = "splitContainer";
            // 
            // splitContainer.Panel1
            // 
            this.splitContainer.Panel1.Controls.Add(this.sectionList);
            this.splitContainer.Panel1MinSize = 200;
            this.splitContainer.Panel2MinSize = 200;
            this.splitContainer.Size = new System.Drawing.Size(800, 426);
            this.splitContainer.SplitterDistance = 266;
            this.splitContainer.TabIndex = 1;
            // 
            // sectionList
            // 
            this.sectionList.Dock = System.Windows.Forms.DockStyle.Fill;
            this.sectionList.FormattingEnabled = true;
            this.sectionList.Location = new System.Drawing.Point(0, 0);
            this.sectionList.Name = "sectionList";
            this.sectionList.Size = new System.Drawing.Size(266, 426);
            this.sectionList.TabIndex = 0;
            this.sectionList.SelectedIndexChanged += new System.EventHandler(this.sectionList_SelectedIndexChanged);
            // 
            // saveFileDialog
            // 
            this.saveFileDialog.DefaultExt = "exe";
            this.saveFileDialog.Filter = "EXE files|*.exe";
            // 
            // TestApp
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(800, 450);
            this.Controls.Add(this.splitContainer);
            this.Controls.Add(this.menuStrip);
            this.Name = "TestApp";
            this.Text = "TestApp";
            this.menuStrip.ResumeLayout(false);
            this.menuStrip.PerformLayout();
            this.splitContainer.Panel1.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.splitContainer)).EndInit();
            this.splitContainer.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.OpenFileDialog openFileDialog;
        private System.Windows.Forms.MenuStrip menuStrip;
        private System.Windows.Forms.ToolStripMenuItem mFile;
        private System.Windows.Forms.SplitContainer splitContainer;
        private System.Windows.Forms.ListBox sectionList;
        private System.Windows.Forms.ToolStripMenuItem mFileLoadEXE;
        private System.Windows.Forms.ToolStripMenuItem mFileSaveEXE;
        private System.Windows.Forms.SaveFileDialog saveFileDialog;
    }
}

