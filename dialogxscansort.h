#ifndef DIALOGXSCANSORT_H
#define DIALOGXSCANSORT_H

#include <QDialog>

namespace Ui {
class DialogXScanSort;
}

class DialogXScanSort : public QDialog
{
    Q_OBJECT

public:
    explicit DialogXScanSort(QWidget *parent = nullptr);
    ~DialogXScanSort();

private:
    Ui::DialogXScanSort *ui;
};

#endif // DIALOGXSCANSORT_H
