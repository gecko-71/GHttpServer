object frmHTTPTester: TfrmHTTPTester
  Left = 0
  Top = 0
  Margins.Left = 4
  Margins.Top = 4
  Margins.Right = 4
  Margins.Bottom = 4
  Caption = 'HTTP Server Tester'
  ClientHeight = 641
  ClientWidth = 897
  Color = clBtnFace
  Font.Charset = DEFAULT_CHARSET
  Font.Color = clWindowText
  Font.Height = -14
  Font.Name = 'Tahoma'
  Font.Style = []
  OnCreate = FormCreate
  PixelsPerInch = 123
  TextHeight = 17
  object pnlControls: TPanel
    Left = 0
    Top = 0
    Width = 897
    Height = 83
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Align = alTop
    TabOrder = 0
    ExplicitWidth = 893
    object lblServerAddress: TLabel
      Left = 21
      Top = 14
      Width = 97
      Height = 17
      Margins.Left = 4
      Margins.Top = 4
      Margins.Right = 4
      Margins.Bottom = 4
      Caption = 'Server Address:'
    end
    object lblPort: TLabel
      Left = 291
      Top = 14
      Width = 31
      Height = 17
      Margins.Left = 4
      Margins.Top = 4
      Margins.Right = 4
      Margins.Bottom = 4
      Caption = 'Port:'
    end
    object edtServerAddress: TEdit
      Left = 115
      Top = 10
      Width = 155
      Height = 25
      Margins.Left = 4
      Margins.Top = 4
      Margins.Right = 4
      Margins.Bottom = 4
      TabOrder = 0
      Text = '127.0.0.1'
    end
    object edtPort: TEdit
      Left = 329
      Top = 10
      Width = 72
      Height = 25
      Margins.Left = 4
      Margins.Top = 4
      Margins.Right = 4
      Margins.Bottom = 4
      NumbersOnly = True
      TabOrder = 1
      Text = '3042'
    end
    object btnRunTests: TButton
      Left = 431
      Top = 8
      Width = 153
      Height = 32
      Margins.Left = 4
      Margins.Top = 4
      Margins.Right = 4
      Margins.Bottom = 4
      Caption = 'Run Tests'
      Font.Charset = DEFAULT_CHARSET
      Font.Color = clWindowText
      Font.Height = -14
      Font.Name = 'Tahoma'
      Font.Style = [fsBold]
      ParentFont = False
      TabOrder = 2
      OnClick = btnRunTestsClick
    end
    object btnClear: TButton
      Left = 605
      Top = 8
      Width = 154
      Height = 32
      Margins.Left = 4
      Margins.Top = 4
      Margins.Right = 4
      Margins.Bottom = 4
      Caption = 'Clear Results'
      TabOrder = 3
      OnClick = btnClearClick
    end
  end
  object mmResults: TMemo
    Left = 0
    Top = 83
    Width = 897
    Height = 558
    Margins.Left = 4
    Margins.Top = 4
    Margins.Right = 4
    Margins.Bottom = 4
    Align = alClient
    Font.Charset = DEFAULT_CHARSET
    Font.Color = clWindowText
    Font.Height = -14
    Font.Name = 'Consolas'
    Font.Style = []
    ParentFont = False
    ReadOnly = True
    ScrollBars = ssBoth
    TabOrder = 1
    ExplicitWidth = 893
    ExplicitHeight = 549
  end
end
