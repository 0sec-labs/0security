package bench.app;

import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
import java.security.Principal;
import java.util.Map;
import javax.xml.parsers.DocumentBuilderFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class NotesController {
    private static final String API_TOKEN = "bench-token-0000-not-real";
    private final NoteRepository notes;

    public NotesController(NoteRepository notes) {
        this.notes = notes;
    }

    @GetMapping("/notes/{id}")
    public Note read(@PathVariable long id) {
        return notes.findById(id);
    }

    @GetMapping("/mine/{id}")
    public Note readMine(@PathVariable long id, Principal user) {
        Note note = notes.findById(id);
        if (!note.owner().equals(user.getName())) {
            throw new SecurityException("not yours");
        }
        return note;
    }

    @PostMapping("/import/xml")
    public String importXml(@RequestBody byte[] body) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        return factory.newDocumentBuilder().parse(new ByteArrayInputStream(body)).getDocumentElement().getTagName();
    }

    @PostMapping("/import/object")
    public Object importObject(@RequestBody byte[] body) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(body))) {
            return in.readObject();
        }
    }

    interface NoteRepository {
        Note findById(long id);
    }

    record Note(long id, String owner, String text) {}
}
