#include <QApplication>
#include <QWidget>
#include <QListView>
#include <QStandardItemModel>
#include <QVBoxLayout>
#include <QTabWidget>
#include "mainwindow.h" // 包含你原本的MainWindow头文件

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    // 创建主窗口
    MainWindow mainWindow; // 假设你有一个自定义的MainWindow类
    mainWindow.setWindowTitle("Main Window Title");

    // 创建数据模型
    QStandardItemModel *model = new QStandardItemModel();

    // 添加数据项
    QStringList fruits;
    fruits << "Apple" << "Banana" << "Cherry" << "Date";

    foreach (const QString &fruit, fruits) {
        QStandardItem *item = new QStandardItem(fruit);
        model->appendRow(item);
    }

    // 创建ListView控件并设置数据模型
    QListView *listView = new QListView();
    listView->setModel(model);

    // 创建垂直布局管理器，并将ListView添加到其中
    QVBoxLayout *layout = new QVBoxLayout();
    layout->addWidget(listView);

    // 假设你的MainWindow有一个QTabWidget作为其主布局
    QTabWidget *tabWidget = new QTabWidget(&mainWindow);
    mainWindow.setCentralWidget(tabWidget);

    // 创建一个新的QWidget作为Tab页，并将布局添加到这个Widget中
    QWidget *tabPage = new QWidget();
    tabPage->setLayout(layout);

    // 将Tab页添加到TabWidget中
    tabWidget->addTab(tabPage, "进程管理");

    // 显示主窗口
    mainWindow.show();

    return app.exec();
}
