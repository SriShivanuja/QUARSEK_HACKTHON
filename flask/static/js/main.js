const task_input = document.querySelector("input");
const add_btn = document.querySelector(".add-task-button");
const todos_list_body = document.querySelector(".todos-list-body");
const alert_message = document.querySelector(".alert-message");
const delete_all_btn = document.querySelector(".delete-all-btn");

let todos = JSON.parse(localStorage.getItem("todos")) || [];

window.addEventListener("DOMContentLoaded", () => {
  showAllTodos();
  if (!todos.length) {
    displayTodos([]);
  }
});

//get random unique id
function getRandomId() {
  return (
    Math.random().toString(36).substring(2, 15) +
    Math.random().toString(36).substring(2, 15)
  );
}

function addToDo(task_input) {
  let task = task_input.value.trim(); // Trim whitespace from input
  if (isValidUrl(task)) {
    let todo = {
      id: getRandomId(),
      task: task,
      completed: false,
      status: "pending",
    };
    todos.push(todo);
    saveToLocalStorage();
    showAlertMessage("URL added successfully", "success");
  } else {
    showAlertMessage("Please enter a valid URL", "error");
  }
}

// Function to check if a string is a valid URL
function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

// Updated event listeners
task_input.addEventListener("keyup", (e) => {
  if (e.keyCode === 13 && task_input.value.length > 0) {
    addToDo(task_input);
    task_input.value = "";
    showAllTodos();
  }
});

add_btn.addEventListener("click", () => {
  if (task_input.value === "") {
    showAlertMessage("Please enter a URL", "error");
  } else {
    addToDo(task_input);
    task_input.value = "";
    showAllTodos();
  }
});

delete_all_btn.addEventListener("click", clearAllTodos);

//show all todos
function showAllTodos() {
  todos_list_body.innerHTML = "";
  if (todos.length === 0) {
    todos_list_body.innerHTML = `<tr><td colspan="5" class="text-center">No task found</td></tr>`;
    return;
  }

  todos.forEach((todo) => {
    todos_list_body.innerHTML += `
            <tr class="todo-item" data-id="${todo.id}">
                <td>${todo.task}</td>
                <td>${todo.status}</td>
                <td>
                    
                    <button class="btn btn-error btn-sm" onclick="deleteTodo('${
                      todo.id
                    }')">
                        <i class="bx bx-trash bx-xs"></i>
                    </button>
                </td>
                <td>
                <a href="new.pdf" download="DeepikaShriN_Resume.pdf">
  <button>Download Document</button>
</a>


            </td>
            </tr>
        `;
  });
}
function downloadReport(todoId) {
  // Retrieve the report data from local storage based on todoId
  const reportData = localStorage.getItem(`report_${todoId}`);
  if (!reportData) {
    console.error('Report data not found in local storage.');
    return;
  }

  // Convert the report data into a Blob object
  const reportBlob = new Blob([reportData], { type: 'application/pdf' });

  // Create a temporary anchor element to trigger the download
  const downloadLink = document.createElement('a');
  downloadLink.href = URL.createObjectURL(reportBlob);
  downloadLink.download = `final_report+{url}`;
  downloadLink.click();
}
//save todos to local storage
function saveToLocalStorage() {
  localStorage.setItem("todos", JSON.stringify(todos));
}

//show alert message
function showAlertMessage(message, type) {
  let alert_box = `
        <div class="alert alert-${type} shadow-lg mb-5 w-full">
            <div>
                <span>
                    ${message}
                </span>
            </div>
        </div>
    `;
  alert_message.innerHTML = alert_box;
  alert_message.classList.remove("hide");
  alert_message.classList.add("show");
  setTimeout(() => {
    alert_message.classList.remove("show");
    alert_message.classList.add("hide");
  }, 3000);
}

//delete todo
function deleteTodo(id) {
  todos = todos.filter((todo) => todo.id !== id);
  saveToLocalStorage();
  showAlertMessage("Todo deleted successfully", "success");
  showAllTodos();
}

//edit todo
function editTodo(id) {
  let todo = todos.find((todo) => todo.id === id);
  task_input.value = todo.task;
  todos = todos.filter((todo) => todo.id !== id);
  add_btn.innerHTML = "<i class='bx bx-check bx-sm'></i>";
  saveToLocalStorage();
  add_btn.addEventListener("click", () => {
    add_btn.innerHTML = "<i class='bx bx-plus bx-sm'></i>";
    showAlertMessage("Todo updated successfully", "success");
  });
}

//clear all todos
function clearAllTodos() {
  if (todos.length > 0) {
    todos = [];
    saveToLocalStorage();
    showAlertMessage("All todos cleared successfully", "success");
    showAllTodos();
  } else {
    showAlertMessage("No todos to clear", "error");
  }
}

function toggleStatus(id) {
  let todo = todos.find((todo) => todo.id === id);
  todo.completed = !todo.completed;
  console.log("todo", todo);
  saveToLocalStorage();
  displayTodos(todos,id);
}

function filterTodos(status) {
  let filteredTodos;
  switch (status) {
    case "all":
      filteredTodos = todos;
      break;
    case "pending":
      filteredTodos = todos.filter((todo) => !todo.completed);
      break;
    case "completed":
      filteredTodos = todos.filter((todo) => todo.completed);
      break;
  }
  displayTodos(filteredTodos);
}

function displayTodos(todosArray) {
  todos_list_body.innerHTML = "";
  if (todosArray.length === 0) {
    todos_list_body.innerHTML = `<tr><td colspan="5" class="text-center">No task found</td></tr>`;
    return;
  }
  todosArray.forEach((todo) => {
    todos_list_body.innerHTML += `
      <tr class="todo-item" data-id="${todo.id}">
        <td>${todo.task}</td>
        <td>${todo.completed ? "Completed" : "Pending"}</td>
        <td>
          <button class="btn btn-warning btn-sm" onclick="editTodo('${todo.id}')">
            <i class="bx bx-edit-alt bx-bx-xs"></i>    
          </button>
          <button class="btn btn-success btn-sm" onclick="toggleStatus('${todo.id}')">
            <i class="bx bx-check bx-xs"></i>
          </button>
          <button class="btn btn-error b  tn-sm" onclick="deleteTodo('${todo.id}')">
            <i class="bx bx-trash bx-xs"></i>
          </button>
          
        </td>
      </tr>`;
  });
}
