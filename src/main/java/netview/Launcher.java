package netview;

import javafx.application.Application;
import netview.ui.NetViewApp;

/** Separate launcher permits a self-contained classpath distribution of JavaFX. */
public final class Launcher {
    private Launcher() {}
    public static void main(String[] args) throws Exception {
        if (args.length > 0 && (args[0].equals("--inspect") || args[0].equals("--capture"))) {
            System.exit(netview.cli.SessionCli.run(args));
            return;
        }
        Application.launch(NetViewApp.class, args);
    }
}
