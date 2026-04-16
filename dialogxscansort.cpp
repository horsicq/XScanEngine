#include "dialogxscansort.h"
#include "ui_dialogxscansort.h"

DialogXScanSort::DialogXScanSort(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::DialogXScanSort)
{
    ui->setupUi(this);
}

DialogXScanSort::~DialogXScanSort()
{
    delete ui;
}
