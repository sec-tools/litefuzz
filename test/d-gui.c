/*
test crash app #4

format string leading to invalid read in a GUI
*/

#include <stdio.h>
#include <string.h>
#include <gtk/gtk.h>

int main(int argc, char *argv[]) {
    gtk_init(&argc, &argv);

    char *data;

    if(argc < 2) {
        data = "%s%s%s%s";
        //data = "%n%n%n%n";
    }
    else {
        data = argv[1];
    }

    printf(data);

    GtkWidget *window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

    gtk_widget_show_all(GTK_WIDGET(window));
    g_signal_connect(G_OBJECT(window), "destroy", G_CALLBACK(gtk_main_quit), NULL);

    gtk_main();

    return 0;
}
